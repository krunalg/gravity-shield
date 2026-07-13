# Pi-hole AI Guardian — Current Implementation Plan

## Goal

Run a local Pi-hole protection daemon that combines deterministic domain feature extraction, local Granite reasoning through Ollama, verified threat-intel sync, and Pi-hole group-based blocking with no cloud dependency.

## Current Architecture

```text
New DNS query
  -> DomainWatcher (tails FTL log)
  -> never-block / skip policy
  -> StateDB TTL-aware seen-domain check
  -> queue.Queue(maxsize=500)
       -> ClassifierWorker (one domain at a time)
          -> subdomain apex dedup (skip LLM if apex blocked)
          -> popularity allowlist (skip LLM if apex in Tranco top list,
             unless known to a threat feed)
          -> features.extractor.extract() with runtime brand map
          -> rule pre-filter (skip LLM if rule_score < RULE_PREFILTER_THRESHOLD)
          -> RDAP domain age lookup (cached in StateDB, fail-open)
          -> DomainClassifier / LLM via Ollama
          -> structured verdict
          -> PiholeClient
          -> gravity.db domainlist
          -> Adaptive Threat Blocklist group
          -> batched pihole reloadlists

Threat-intel feed hit
  -> ThreatIntelSyncer (every 6h)
  -> popularity list sync (Tranco, weekly)
  -> feed freshness alerting (warn if feed not synced in 24h)
  -> dedupe against StateDB
  -> popular-apex guard (never auto-block a Tranco-ranked apex —
     feeds list URLs on compromised legitimate sites)
  -> features.extractor.extract(threat_context=...) with runtime brand map
  -> rule-based scoring only (no LLM)
  -> PiholeClient
  -> Adaptive Threat Blocklist group
```

## Implemented Components

- `features/` deterministic extraction package
- `classifier.py` structured-evidence LLM prompt with `_build_evidence()` distillation
- `state_db.py` classification feature metadata columns and migration, TTL-aware seen-domain tracking
- `domain_policy.py` centralized never-block policy
- `pihole_client.py` Pi-hole DB writer, never-block final guard, group assignment, reload batching
- `syncer.py` threat-intel feed verification before blocking, feed freshness alerting
- `watcher.py` queue-based real-time query processing with subdomain apex deduplication, popularity allowlist, and rule pre-filter
- `popularity.py` Tranco top-list fetcher (zip or plain CSV)
- `brands.py` runtime brand map derived from the Tranco snapshot + `EXTRA_BRANDS` seed
- `rdap.py` domain registration age via RDAP (IANA bootstrap), StateDB-cached
- `daemon.py` thread supervisor — restarts watcher or worker if either dies

## Feature Extraction

`features.extractor.extract(domain, threat_context=None)` returns:

- lexical metrics
- Shannon and normalized entropy
- TLD risk
- digit metrics
- hyphen metrics
- punycode/homograph signal
- brand similarity (brand list derived at runtime — see Brand Detection)
- DGA score
- deterministic rule score, severity, and rule reasons
- optional threat-intel context

The LLM must reason over this evidence. It must not calculate feature values itself.

`_build_evidence()` in `classifier.py` distils the full feature dict into a concise flat JSON (removes verbose nested lexical fields) before sending to the LLM.

## Brand Detection (data-driven)

No hardcoded brand list. `brands.get_brand_map(state_db)` builds
`{brand_token: official_apex}` at runtime:

- Source: StateDB `popular_domains` (Tranco snapshot), apexes ranked within
  `BRAND_SOURCE_RANK_THRESHOLD` (default 1000).
- Token = SLD of the apex; tokens shorter than `BRAND_MIN_TOKEN_LENGTH`
  (default 5) are dropped to avoid fuzzy false positives.
- `EXTRA_BRANDS` config seed covers targets below the rank cutoff (regional
  banks etc.) and overrides derived entries.
- ClassifierWorker caches the map for `BRAND_MAP_REFRESH_SECONDS` (1h);
  the syncer derives it once per sync cycle. On DB failure, detection falls
  back to `EXTRA_BRANDS` alone.
- `features/brand.py` `detect(domain, brands=None)` skips the Levenshtein pass
  when the length gap alone makes the match threshold unreachable, keeping
  feed-scale verification cheap.

## RDAP Domain Age Scoring

`rdap.get_domain_age_days(apex, state_db)` runs only for domains that survive
the rule pre-filter (post-prefilter, pre-LLM — low volume, so one network call
per new suspicious domain is fine). Feeds are never RDAP-checked.

- Server discovery: IANA bootstrap (`RDAP_BOOTSTRAP_URL`), TLD → base URL,
  cached in memory for 7 days.
- Registration date = RDAP `events[eventAction=registration].eventDate`.
- Cache: StateDB `domain_registration` — successes cached forever (a
  registration date never changes), failures negative-cached for
  `RDAP_NEGATIVE_CACHE_DAYS` (7).
- Scoring in `features/rules.py`: age ≤ `DOMAIN_AGE_NEW_DAYS` (30) →
  +`DOMAIN_AGE_NEW_WEIGHT` (25); age ≤ `DOMAIN_AGE_RECENT_DAYS` (180) →
  +`DOMAIN_AGE_RECENT_WEIGHT` (10). Unknown age = no signal (fail-open).
- Evidence: `domain_age_days` included in the LLM evidence JSON with prompt
  guidance; `null` means unknown and must be ignored.
- `RDAP_ENABLED = False` disables lookups entirely.

## Popularity Allowlist

Tranco top list synced weekly into StateDB `popular_domains` (atomic replace;
empty fetch never wipes the list). In the watcher, apexes ranked within
`POPULARITY_RANK_THRESHOLD` skip the LLM unless a threat feed knows the
domain. In the syncer, a Tranco-ranked apex is never auto-blocked from a feed.

## Queue-Based Classification

`DomainWatcher` and `ClassifierWorker` run as separate threads connected by a `queue.Queue(maxsize=500)`.

- Watcher: enqueues new domains with `put_nowait()` — drops domain and logs warning if queue is full.
- Worker: dequeues one domain at a time — never blocks, never calls Ollama in parallel.

This decouples log reading from LLM latency. Bursts of DNS queries fill the queue without stalling log processing.

## Subdomain Apex Deduplication

In `ClassifierWorker._handle_domain()`:

1. Extract the registered domain (apex) using `registered_domain(domain)`.
2. Look up the last verdict for the apex via `StateDB.get_last_verdict(apex)`.
3. If the apex is already blocked, block the subdomain directly (no LLM call). Comment: `AI:SUBDOMAIN:<apex>`.

## Rule Pre-Filter

Before calling the LLM:

- Extract features and check `rule_score`.
- If `rule_score < RULE_PREFILTER_THRESHOLD` (default 15), auto-allow without LLM call.
- Log a `SAFE` classification with reason `Rule pre-filter: score=N`.

This eliminates LLM calls for clearly benign DNS queries (most home traffic).

## Classification TTL

`StateDB.filter_unseen()` uses a TTL-aware query:

```sql
SELECT domain FROM seen_domains WHERE domain IN (...)
  AND last_seen >= datetime('now', '-7 days')
```

Domains not seen in `SEEN_DOMAIN_TTL_DAYS` (default 7) are treated as unseen and re-classified. `mark_domain_seen()` updates `last_seen` on every hit (upsert).

## Feed Freshness Alerting

`ThreatIntelSyncer._check_feed_freshness()` runs at the start of each sync cycle:

- Calls `StateDB.hours_since_last_sync(feed_name)` for each feed.
- Logs `WARNING` if hours elapsed > `FEED_STALENESS_WARN_HOURS` (default 24).
- Logs `INFO` if feed has never synced.

## Classifier Output Schema

The LLM should return JSON only:

```json
{
  "classification": "PHISHING",
  "confidence": 0.97,
  "severity": "HIGH",
  "risk_score": 91,
  "reasons": ["Brand similarity to PayPal", "Suspicious TLD"],
  "recommended_action": "BLOCK"
}
```

Blocking requires:

- `recommended_action == "BLOCK"` or classification in `CATEGORIES_TO_BLOCK`
- `confidence >= BLOCK_CONFIDENCE_THRESHOLD`
- deterministic `rule_score >= BLOCK_RULE_SCORE_FLOOR` — the LLM-returned
  `risk_score` is advisory only; the model's arithmetic never gates a block
- not covered by the never-block policy

## Pi-hole Group Requirement

All new blocked entries must be assigned to:

```text
Adaptive Threat Blocklist
```

Implementation:

- `PIHOLE_BLOCK_GROUP_NAME = "Adaptive Threat Blocklist"`
- `PiholeClient` creates the group when needed.
- `PiholeClient` inserts mappings into `domainlist_by_group`.
- Historical entries are not migrated automatically.

## Reload Policy

Blocked domains are written to `gravity.db` immediately. Pi-hole reload is debounced:

```python
PIHOLE_RELOAD_INTERVAL_SECONDS = 60
```

Set `PIHOLE_RELOAD_INTERVAL_SECONDS = 0` to reload immediately.

On daemon shutdown, any pending reload is flushed.

## Threat Intel Verification

Feed domains are verified using deterministic feature extraction + rule scoring only. Ollama is **not** called for feed domains.

Rationale: URLhaus contains 40k+ entries. Running each through a local LLM at ~90s/call would take days per sync cycle. Rule-based verification is sufficient because:

- URLhaus domains receive `urlhaus_hit=True` in `threat_context`, which sets `rule_score = 100` → always passes.
- OpenPhish domains are scored by lexical features, entropy, TLD risk, and DGA heuristics.
- Domains scoring below `RULE_SCORE_THRESHOLD` are skipped.

Ollama is reserved for real-time DNS query classification in `watcher.py` (one domain at a time, low volume).

## Threat Feeds

Current default feeds:

- URLhaus
- OpenPhish

Removed/default-disabled feeds:

- Feodo domain feed: retired / not domain-based
- DigitalSide OSINT: unresolvable endpoint

Do not reintroduce feed URLs without verification and tests.

## Never-Block Policy

Central policy:

- `NEVER_BLOCK_DOMAINS` / `NEVER_BLOCK_SUFFIXES` — infrastructure only
  (`pi.hole`, `localhost`, `.local`, `.lan`, ...). Established public domains
  are protected data-driven by the popularity allowlist and feed guard, not by
  hardcoded lists.
- `USER_ALLOWLIST_PATH` (default `~/pihole-ai/allowlist.txt`) — one entry per
  line, `domain.com` exact or `.domain.com` suffix; mtime-cached, picked up
  without restart. This is the false-positive recovery path.
- `domain_policy.is_never_block_domain()`

This is enforced by `PiholeClient` before DB insertion, not only by the watcher.

## State DB

`classifications` stores:

- domain
- category
- confidence
- reason
- blocked
- classified_at
- entropy
- dga_score
- rule_score
- brand
- brand_confidence
- tld
- tld_risk
- is_punycode

Existing DBs are migrated with `ALTER TABLE` on startup.

## Runtime Commands

```bash
make test
make daemon-status
make logs
sudo journalctl -u pihole-ai-$USER -f
```

Inspect classifications:

```bash
sqlite3 state.db \
  "SELECT domain, category, confidence, rule_score, blocked FROM classifications ORDER BY classified_at DESC LIMIT 20"
```

Inspect Pi-hole blocks:

```bash
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT domain, comment FROM domainlist WHERE comment LIKE 'AI:%' OR comment LIKE 'TI:%' LIMIT 20"
```

Inspect group assignment:

```bash
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT d.domain, g.name FROM domainlist d JOIN domainlist_by_group dg ON dg.domainlist_id=d.id JOIN \"group\" g ON g.id=dg.group_id WHERE g.name='Adaptive Threat Blocklist' LIMIT 20"
```

## Test Coverage

Current suite: 199 tests.

Covered areas:

- feature extraction
- classifier prompt and schema parsing
- Pi-hole DB insertion
- `Adaptive Threat Blocklist` assignment
- never-block final guard
- reload batching
- threat-intel parsing
- threat-intel rule-based verification (URLhaus always passes, low-score domains skipped)
- feed error isolation (one bad feed does not crash the sync cycle)
- TI block expiry (last_seen refresh on re-listing, comment-prefix-guarded removal, disable with 0)
- shared-hosting detection (PSL private section parsing/sync, full-hostname feed blocks, watcher popularity bypass, brand detection on user label)
- ASN reputation (ASN-DROP parsing/sync, Team Cymru lookup, StateDB cache, rule weight, watcher fail-open)
- TLS certificate analysis (opt-in default off, verify-failure signal, cert-age weight, cache, fail-open)
- legacy block migration into the Adaptive Threat Blocklist group (idempotent, `make migrate-blocks`)
- watcher skip policy
- queue-based enqueue and drop-when-full behavior
- rule pre-filter (low-score domains skip LLM)
- popularity allowlist (watcher) and popular-apex feed guard (syncer)
- brand map derivation (Tranco SLD tokens, min length, EXTRA_BRANDS override)
- deterministic block gate (LLM risk_score cannot force or veto a block)
- user allowlist file (exact/suffix entries, live reload)
- RDAP bootstrap/date parsing, age caching (positive + negative), rule scoring, watcher fail-open wiring
- state DB persistence/migration (TTL-aware seen-domain tracking, get_last_verdict, hours_since_last_sync)
- Ollama HTTP wrapper

## Future Work

- dashboard for classification history
- configurable custom allowlist/blocklist import
