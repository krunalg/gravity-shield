# Pi-hole AI Guardian

Local AI-assisted DNS threat classification and threat-intel sync for Pi-hole, with no cloud dependency.

## What It Does

- Watches Pi-hole DNS query logs in real time.
- Extracts deterministic domain features before asking a local LLM to reason.
- Skips the LLM entirely for clearly benign domains (rule pre-filter).
- Blocks subdomains of already-blocked apex domains directly, without an LLM call.
- Re-classifies domains not seen in 7 days (classification TTL).
- Syncs threat-intel feeds (URLhaus, OpenPhish) every 6h using rule-based scoring — fast, no LLM calls.
- Alerts when a feed has not synced in 24h.
- Writes malicious domains to Pi-hole's `Adaptive Threat Blocklist` group.
- Batches Pi-hole list reloads instead of reloading after every insert.
- Keeps a central never-block policy for critical/known-legitimate domains.

## Architecture

```text
Pi-hole FTL log
  -> DomainWatcher (tails log, enqueues domains)
  -> queue.Queue(maxsize=500)
       -> ClassifierWorker (one domain at a time)
          -> subdomain apex check (skip LLM if apex already blocked)
          -> deterministic feature extraction
          -> rule pre-filter (skip LLM if rule_score < 15)
          -> local LLM reasoning via Ollama
          -> structured verdict (JSON)
          -> Pi-hole gravity.db
          -> Adaptive Threat Blocklist group

Threat feeds (URLhaus, OpenPhish)
  -> ThreatIntelSyncer (every 6h)
  -> feed freshness check (warn if >24h stale)
  -> dedupe against state DB
  -> deterministic feature extraction + rule scoring
  -> Pi-hole gravity.db
  -> Adaptive Threat Blocklist group
```

The LLM is only used for real-time DNS query classification (one domain at a time, low volume). Threat-intel feeds use rule-based scoring because feeds can contain 40k+ entries — calling a local LLM per domain would take days. The queue decouples log reading from LLM latency so bursts of DNS queries never stall log processing.

## Requirements

- Raspberry Pi (or any Linux host) with Pi-hole v6.4+
- Python 3.11+
- GNU Make
- [Ollama](https://ollama.com) with any compatible model

```bash
ollama pull granite4.1:3b   # or any model you prefer
ollama serve
```

## Getting Started

```bash
git clone https://github.com/krunalg/gravity-shield.git pihole-ai
cd pihole-ai
make install
make test
make setup
```

The interactive setup wizard prompts for:
- Installation directory
- SSH username (for file permission setup)
- Ollama model name
- Pi-hole paths

It then creates:
- `.venv` with all dependencies
- `config_local.py` with your local overrides
- systemd service `pihole-ai-$USER`
- sudoers rule for passwordless `pihole reloadlists`
- ACL permissions for Pi-hole DB and log access

Start the daemon:

```bash
make daemon-start
make daemon-status
```

To update and restart:

```bash
git pull
make daemon-stop
make daemon-start
```

To fully reset and re-run setup:

```bash
make re-setup
```

## Verify It's Working

```bash
make logs
```

Check recent classifications in state DB:

```bash
sqlite3 state.db \
  "SELECT domain, category, confidence, rule_score, blocked FROM classifications ORDER BY classified_at DESC LIMIT 20"
```

Check domains added to Pi-hole:

```bash
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT domain, comment FROM domainlist WHERE comment LIKE 'AI:%' OR comment LIKE 'TI:%' LIMIT 20"
```

Check group assignment:

```bash
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT d.domain, g.name FROM domainlist d
   JOIN domainlist_by_group dg ON dg.domainlist_id=d.id
   JOIN \"group\" g ON g.id=dg.group_id
   WHERE g.name='Adaptive Threat Blocklist' LIMIT 20"
```

## Classification Flow

Feature extraction runs deterministically before the LLM sees the domain:

- lexical metrics (length, label count, vowel/consonant ratio, dictionary words)
- Shannon entropy
- digit and hyphen metrics
- punycode / homograph signal
- TLD risk
- brand similarity (Levenshtein + leet-decode)
- DGA score heuristic
- rule score and deterministic reasons
- threat-intel context when available

The LLM receives this structured evidence as JSON and returns:

```json
{
  "classification": "PHISHING",
  "confidence": 0.97,
  "severity": "HIGH",
  "risk_score": 91,
  "reasons": ["Brand impersonation", "Suspicious TLD"],
  "recommended_action": "BLOCK"
}
```

A domain is blocked only when action/category, confidence, and rule score all pass configured thresholds.

## Pi-hole Group Behavior

Every newly blocked domain is mapped to:

```
Adaptive Threat Blocklist
```

`PiholeClient` creates the group if it doesn't exist and inserts mappings into `domainlist_by_group`. Make sure this group is assigned to your Pi-hole clients in the Pi-hole admin interface for blocks to take effect.

## Reload Behavior

Domains are written to `gravity.db` immediately, but Pi-hole reloads are batched:

```python
PIHOLE_RELOAD_INTERVAL_SECONDS = 60
```

Set it to `0` in `config_local.py` to reload immediately after each insert.

## Never-Block Policy

Domains and suffixes configured in `config.py`:

```python
NEVER_BLOCK_DOMAINS
NEVER_BLOCK_SUFFIXES
```

This policy is enforced at the final Pi-hole insert layer — no classifier or feed result can insert protected domains.

## Configuration

Defaults in `config.py`; local overrides in `config_local.py` (generated by `make setup`).

Key settings:

```python
OLLAMA_MODEL = "granite4.1:3b"       # swap to any Ollama-compatible model
BLOCK_CONFIDENCE_THRESHOLD = 0.80
RULE_SCORE_THRESHOLD = 70            # minimum risk_score to block
RULE_PREFILTER_THRESHOLD = 15        # skip LLM entirely if rule_score below this
SEEN_DOMAIN_TTL_DAYS = 7            # re-classify domains not seen in N days
FEED_STALENESS_WARN_HOURS = 24      # warn if feed not synced in N hours
DGA_THRESHOLD = 0.70
ENTROPY_THRESHOLD = 3.8
BRAND_MATCH_THRESHOLD = 0.80
THREAT_INTEL_INTERVAL_HOURS = 6
PIHOLE_BLOCK_GROUP_NAME = "Adaptive Threat Blocklist"
PIHOLE_RELOAD_INTERVAL_SECONDS = 60
```

## Makefile Targets

| Target | Description |
|---|---|
| `make install` | Create `.venv` and install dependencies |
| `make test` | Run test suite |
| `make setup` | Interactive setup wizard |
| `make reset` | Stop daemon, delete `config_local.py`, `state.db`, logs |
| `make re-setup` | `reset` then `setup` |
| `make daemon-start` | Start systemd service |
| `make daemon-stop` | Stop systemd service |
| `make daemon-status` | Show service status |
| `make daemon-restart` | Restart service |
| `make fix-permissions` | Re-apply ACLs on gravity.db and FTL log (run after Pi-hole update) |
| `make logs` | Tail daemon log |
| `make clean` | Remove `.venv` and `__pycache__` |
| `make help` | Show all targets |

## Tests

```bash
make test
```

Current suite: 55 tests. All external services (Ollama, Pi-hole, threat feeds) are mocked.

## Project Structure

```text
config.py            static defaults
config_local.py      generated by setup (gitignored)
daemon.py            main entry point, starts both threads
watcher.py           tails FTL log, real-time classification
syncer.py            threat-intel feed sync (rule-based)
classifier.py        LLM reasoning via Ollama
ollama_client.py     Ollama HTTP wrapper (streaming NDJSON)
pihole_client.py     gravity.db writer, group assignment, reload batching
state_db.py          classification history and threat domain deduplication
threat_intel.py      feed fetchers and parsers
domain_policy.py     never-block policy
features/
  extractor.py       single entry point — orchestrates all detectors
  lexical.py
  entropy.py
  digits.py
  hyphens.py
  punycode.py
  tld.py
  brand.py
  dga.py
  rules.py
tests/
```

## Troubleshooting

**Ollama not responding:**

```bash
curl http://localhost:11434/api/tags
ollama list
```

**Daemon not starting:**

```bash
sudo systemctl status pihole-ai-$USER
sudo journalctl -u pihole-ai-$USER -n 100
```

**Domains not appearing in Pi-hole:**

```bash
# Check gravity.db directly
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT domain, comment FROM domainlist WHERE comment LIKE 'TI:%' LIMIT 10"

# Check reload ran
sudo -n pihole reloadlists
```

**Sync history:**

```bash
sqlite3 state.db "SELECT * FROM sync_log ORDER BY synced_at DESC LIMIT 10"
```

## Contributing

1. Fork the repo and create a feature branch.
2. Add or update tests — `make test` must pass with no failures.
3. Keep all thresholds and tunables in `config.py`.
4. Never bypass `PiholeClient` for Pi-hole writes.
5. Never call Ollama from `syncer.py` — rule-based scoring only for feeds.
6. Open a pull request with a clear description of the change and why.

No cloud APIs, no telemetry, no hardcoded paths.

## License

MIT License. See [LICENSE](LICENSE) for details.
