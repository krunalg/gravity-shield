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
          -> features.extractor.extract()
          -> rule pre-filter (skip LLM if rule_score < RULE_PREFILTER_THRESHOLD)
          -> DomainClassifier / LLM via Ollama
          -> structured verdict
          -> PiholeClient
          -> gravity.db domainlist
          -> Adaptive Threat Blocklist group
          -> batched pihole reloadlists

Threat-intel feed hit
  -> ThreatIntelSyncer (every 6h)
  -> feed freshness alerting (warn if feed not synced in 24h)
  -> dedupe against StateDB
  -> features.extractor.extract(threat_context=...)
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
- `watcher.py` queue-based real-time query processing with subdomain apex deduplication and rule pre-filter
- `daemon.py` thread supervisor — restarts watcher or worker if either dies

## Feature Extraction

`features.extractor.extract(domain, threat_context=None)` returns:

- lexical metrics
- Shannon and normalized entropy
- TLD risk
- digit metrics
- hyphen metrics
- punycode/homograph signal
- brand similarity
- DGA score
- deterministic rule score, severity, and rule reasons
- optional threat-intel context

The LLM must reason over this evidence. It must not calculate feature values itself.

`_build_evidence()` in `classifier.py` distils the full feature dict into a concise flat JSON (removes verbose nested lexical fields) before sending to the LLM.

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
- `risk_score >= RULE_SCORE_THRESHOLD`
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

- `NEVER_BLOCK_DOMAINS`
- `NEVER_BLOCK_SUFFIXES`
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

Current suite: 55 tests.

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
- watcher skip policy
- queue-based enqueue and drop-when-full behavior
- rule pre-filter (low-score domains skip LLM)
- state DB persistence/migration (TTL-aware seen-domain tracking, get_last_verdict, hours_since_last_sync)
- Ollama HTTP wrapper

## Future Work

- WHOIS age scoring
- DNS/ASN reputation
- TLS certificate analysis
- dashboard for classification history
- migration command for historical AI/TI blocks into `Adaptive Threat Blocklist`
- configurable custom allowlist/blocklist import
