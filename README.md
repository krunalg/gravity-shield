# Pi-hole AI Guardian

Local AI-assisted DNS threat classification and threat-intel sync for Pi-hole.

## What It Does

- Watches Pi-hole DNS query logs in real time.
- Extracts deterministic domain features before asking Granite to reason.
- Verifies threat-intel feed hits with the same classifier before blocking.
- Writes malicious domains to Pi-hole’s `Adaptive Threat Blocklist` group.
- Batches Pi-hole list reloads instead of reloading after every insert.
- Keeps a central never-block policy for critical/known-legitimate domains.

## Architecture

```text
Pi-hole FTL log
  -> DomainWatcher
  -> feature extraction
  -> Granite reasoning via Ollama
  -> structured verdict
  -> Pi-hole gravity.db
  -> Adaptive Threat Blocklist group

Threat feeds (URLhaus, OpenPhish)
  -> ThreatIntelSyncer
  -> dedupe
  -> feature extraction + Granite verification
  -> Pi-hole gravity.db
  -> Adaptive Threat Blocklist group
```

## Requirements

- Raspberry Pi with Pi-hole v6.4+
- Python 3.11+
- GNU Make
- Ollama with `granite4.1:3b`

```bash
ollama pull granite4.1:3b
ollama serve
```

## Install

```bash
git clone <repo> pihole-ai
cd pihole-ai
make install
make test
make setup
```

The setup wizard creates:
- `.venv`
- `config_local.py`
- systemd service `pihole-ai-$USER`
- sudoers rule for `pihole reloadlists`
- permissions for Pi-hole DB/log access

## Verify

```bash
make daemon-status
make logs
```

Check recent classifications:

```bash
sqlite3 state.db \
  "SELECT domain, category, confidence, rule_score, blocked FROM classifications ORDER BY classified_at DESC LIMIT 20"
```

Check Pi-hole blocks:

```bash
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT domain, comment FROM domainlist WHERE comment LIKE 'AI:%' OR comment LIKE 'TI:%' LIMIT 20"
```

Check the block group:

```bash
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT id, name FROM \"group\" WHERE name='Adaptive Threat Blocklist'"
```

## Classification Flow

The classifier no longer sends only the raw domain to Granite. It first builds structured evidence:

- lexical metrics
- Shannon entropy
- digit and hyphen metrics
- punycode/homograph signal
- TLD risk
- brand similarity
- DGA score
- rule score and deterministic reasons
- threat-intel context when available

Granite returns JSON:

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

A domain is blocked only when action/category, confidence, and rule score pass configured thresholds.

## Pi-hole Group Behavior

Every newly blocked domain is mapped to:

```text
Adaptive Threat Blocklist
```

`PiholeClient` creates the group when Pi-hole group tables are present and inserts mappings into `domainlist_by_group`.

Existing historical entries are not automatically migrated.

## Reload Behavior

Domains are written to `gravity.db` immediately, but Pi-hole reloads are batched:

```python
PIHOLE_RELOAD_INTERVAL_SECONDS = 60
```

Set it to `0` in `config_local.py` to reload immediately.

## Never-Block Policy

Protected domains and suffixes are configured in:

```python
NEVER_BLOCK_DOMAINS
NEVER_BLOCK_SUFFIXES
```

This policy is enforced at the final Pi-hole insert layer, so even a mistaken classifier or feed result cannot insert protected domains.

## Configuration

Defaults live in `config.py`; local overrides live in `config_local.py`.

Important settings:

```python
OLLAMA_MODEL = "granite4.1:3b"
BLOCK_CONFIDENCE_THRESHOLD = 0.80
RULE_SCORE_THRESHOLD = 70
DGA_THRESHOLD = 0.70
ENTROPY_THRESHOLD = 3.8
BRAND_MATCH_THRESHOLD = 0.80
THREAT_INTEL_INTERVAL_HOURS = 6
PIHOLE_BLOCK_GROUP_NAME = "Adaptive Threat Blocklist"
PIHOLE_RELOAD_INTERVAL_SECONDS = 60
```

## Tests

```bash
make test
```

Current suite: 44 tests. All external services are mocked.

## Project Structure

```text
config.py
config_local.py
daemon.py
watcher.py
syncer.py
classifier.py
ollama_client.py
pihole_client.py
state_db.py
threat_intel.py
domain_policy.py
features/
  extractor.py
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

Ollama:

```bash
curl http://localhost:11434/api/tags
ollama list
```

Daemon:

```bash
sudo systemctl status pihole-ai-$USER
sudo journalctl -u pihole-ai-$USER -n 100
```

Reload permission:

```bash
sudo -n pihole reloadlists
```

State DB:

```bash
sqlite3 state.db "SELECT * FROM sync_log ORDER BY synced_at DESC LIMIT 10"
sqlite3 state.db "SELECT * FROM classifications ORDER BY classified_at DESC LIMIT 5"
```
