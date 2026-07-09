# Pi-hole AI Guardian

Real-time AI-powered DNS domain classification + automated threat intelligence sync for Pi-hole.

## What It Does

- **Real-time Classifier:** Watches Pi-hole's FTL log, extracts new domains, classifies them via local Ollama/Granite3.3, auto-blocks malware/phishing/C2 with >80% confidence
- **Threat Intel Syncer:** Fetches domain IOC feeds (URLhaus, DigitalSide, OpenPhish) every 6 hours, deduplicates, bulk-inserts new malicious domains into Pi-hole denylist
- **Zero Cloud Dependency:** All processing local — Ollama runs on-device, no external APIs needed
- **State Tracking:** SQLite DB tracks seen domains (avoid re-classifying) + classification history + sync logs

## Architecture

```
Pi-hole FTL log ──► DomainWatcher ──► Ollama Classifier ──► Auto-Block ──┐
                                                                           ▼
Threat Intel Feeds ──► ThreatIntelSyncer ──► Dedup + Sync ──────────────► Pi-hole Denylist
(URLhaus, OpenPhish, etc)      (every 6h)
```

## Getting Started

### Prerequisites

Before installing, verify:
- **Raspberry Pi** with Pi-hole v6.4+ running
- **Ollama** installed with `granite3.3:2b` model already pulled
  ```bash
  ollama pull granite3.3:2b
  ollama serve  # Verify running on localhost:11434
  ```
- **Python 3.11+** installed
- **GNU Make** installed
- **Network:** Pi-hole accessible via SSH

### Step 1: Clone & Navigate

```bash
git clone <repo> pihole-ai && cd pihole-ai
make help          # Show all available targets
```

### Step 2: Install Dependencies

```bash
make install       # Creates venv + installs requests, watchdog, pytest
```

Verify installation:
```bash
make test          # Run 31 tests (should all PASS)
```

### Step 3: Run Setup Wizard

```bash
make setup         # Interactive configuration
```

The wizard will prompt you for:

| Prompt | Default | Example |
|--------|---------|---------|
| SSH Username | `$USER` | `krunal` |
| Pi-hole IP/hostname | `192.168.68.104` | `192.168.68.104` or `pihole.local` |
| Pi-hole Admin Password | (none) | `spider123#` |
| Installation directory | `$HOME/pihole-ai` | `/home/krunal/pihole-ai` |
| Ollama API URL | `http://localhost:11434` | `http://localhost:11434` |
| Ollama Model | `granite3.3:2b` | `granite3.3:2b` |

After confirming, the wizard will:
1. Create Python virtual environment
2. Generate `config_local.py` with your settings
3. Generate systemd service: `/etc/systemd/system/pihole-ai-$USER.service`
4. Create sudoers rule: `/etc/sudoers.d/pihole-ai-$USER` (allows reloadlists)
5. Start the daemon

### Step 4: Verify Installation

```bash
make daemon-status       # Check if daemon is running
make logs               # Watch live classification logs
```

Expected output in logs:
```
Classified google.com: SAFE (99%) → allow | Legitimate CDN
Classified tracker.example.com: TRACKER (85%) → allow | Analytics domain
Classified evil-c2-beacon.xyz: MALWARE (92%) → BLOCK | DGA pattern
AUTO-BLOCKED evil-c2-beacon.xyz | MALWARE (92%) | DGA pattern
```

### Step 5: Check Pi-hole Denylist

Verify domains are being blocked:

```bash
# View AI-classified blocks
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT domain, comment FROM domainlist WHERE comment LIKE 'AI:%' LIMIT 10"

# View threat intel blocks
sudo sqlite3 /etc/pihole/gravity.db \
  "SELECT domain, comment FROM domainlist WHERE comment LIKE 'TI:%' LIMIT 10"
```

### Step 6: Monitor Classification History

```bash
# Check recent classifications
sqlite3 state.db \
  "SELECT domain, category, confidence, blocked FROM classifications ORDER BY classified_at DESC LIMIT 20"

# Check threat intel sync history
sqlite3 state.db \
  "SELECT feed_name, domains_added, synced_at FROM sync_log ORDER BY synced_at DESC LIMIT 10"
```

### All Set!

Daemon is now running in background and will:
- Monitor DNS queries in real-time
- Sync threat intel every 6 hours
- Auto-block malicious domains
- Log all decisions to `state.db`

## Usage

### Common Commands

```bash
make test                    # Run full test suite (31 tests)
make daemon-start            # Start daemon
make daemon-stop             # Stop daemon
make daemon-status           # Check daemon status
make logs                    # Tail live daemon logs
make clean                   # Remove venv + caches
```

### Manual Daemon

```bash
source .venv/bin/activate
python daemon.py
```

## Monitoring

### View AI Classifications

```bash
tail -f logs/pihole-ai.log
```

Example output:
```
Classified evil-c2-beacon.ru: MALWARE (95%) → BLOCK | DGA pattern
AUTO-BLOCKED evil-c2-beacon.ru | MALWARE (95%) | DGA pattern
```

### Check State Database

```bash
sqlite3 state.db "SELECT domain, category, confidence FROM classifications WHERE blocked=1 LIMIT 20"
```

### Check Threat Intel Sync History

```bash
sqlite3 state.db "SELECT feed_name, domains_added, synced_at FROM sync_log ORDER BY synced_at DESC LIMIT 10"
```

### Check Pi-hole Denylist

```bash
sudo sqlite3 /etc/pihole/gravity.db "SELECT domain, comment FROM domainlist WHERE comment LIKE 'AI:%' OR comment LIKE 'TI:%' LIMIT 20"
```

## Configuration

All settings in `config.py`. User overrides via `config_local.py` (auto-generated by setup wizard).

### Key Settings

- `BLOCK_CONFIDENCE_THRESHOLD = 0.80` — blocks only if confidence > 80%
- `CATEGORIES_TO_BLOCK = {"MALWARE", "PHISHING", "C2", "RANSOMWARE"}` — threat types to block
- `THREAT_INTEL_INTERVAL_HOURS = 6` — feed sync interval
- `OLLAMA_TIMEOUT = 30` — seconds per classification

## Project Structure

```
├── Makefile                  # Build + daemon management
├── config.py                 # Static defaults
├── config_local.py           # User config (generated at install)
├── setup.sh                  # Interactive setup wizard
│
├── Core Components
├── state_db.py               # SQLite tracking (seen domains, classifications, syncs)
├── pihole_client.py          # FTL log parser + denylist writer
├── ollama_client.py          # Ollama REST API wrapper with retry
├── classifier.py             # AI domain classification engine
├── threat_intel.py           # IOC feed fetcher + parser
│
├── Daemon
├── watcher.py                # Real-time log watcher thread
├── syncer.py                 # Threat intel sync thread
├── daemon.py                 # Main entry point
├── pihole-ai.service.tpl     # Systemd unit template
│
└── Tests
    ├── test_state_db.py      # 7 tests
    ├── test_pihole_client.py # 6 tests
    ├── test_ollama_client.py # 4 tests
    ├── test_classifier.py    # 7 tests
    ├── test_threat_intel.py  # 7 tests
    └── fixtures/             # Test data
```

## Testing

```bash
make test          # Run all 31 tests
```

All tests mock external APIs (Ollama, Pi-hole DB, feeds) — no real API calls.

## Troubleshooting

### Daemon Not Starting

```bash
sudo systemctl status pihole-ai-$USER
sudo journalctl -u pihole-ai-$USER -n 50
```

### Ollama Connection Failed

Verify Ollama is running:
```bash
curl http://localhost:11434/
```

### Pi-hole DB Lock

Ensure Pi-hole FTL isn't modifying DB:
```bash
sudo systemctl restart pihole-FTL
```

## Development

### Add New Threat Intel Feed

Edit `config.py`, add to `THREAT_INTEL_FEEDS`:

```python
{
    "name": "Feed Name",
    "url": "https://feed.url/domains.txt",
    "comment_prefix": "#",
    "category": "MALWARE",
}
```

### Adjust Classification Thresholds

Edit `config.py`:
```python
BLOCK_CONFIDENCE_THRESHOLD = 0.75  # Lower = more aggressive blocking
CATEGORIES_TO_BLOCK = {"MALWARE", "PHISHING"}  # Add/remove categories
```

## Performance

- **Classification latency:** ~2-3 seconds per domain (Granite on RPi)
- **Threat intel sync:** ~30 seconds for 5 feeds
- **Memory footprint:** ~100-150MB (daemon + model overhead)
- **Disk usage:** ~1-2MB for state DB (grows ~100KB/day)

## License

MIT

## Support

Issues & PRs welcome. For questions, check logs first:
```bash
make logs
sqlite3 state.db "SELECT * FROM classifications ORDER BY classified_at DESC LIMIT 5"
```
