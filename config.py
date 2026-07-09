# Static defaults — overridden by config_local.py for user-specific values
import os

# Ollama
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "granite3.3:2b"
OLLAMA_TIMEOUT = 30
OLLAMA_MAX_RETRIES = 2

# Classifier thresholds
BLOCK_CONFIDENCE_THRESHOLD = 0.80
CATEGORIES_TO_BLOCK = {"MALWARE", "PHISHING", "C2", "RANSOMWARE"}
CATEGORIES_SAFE = {"AD", "TRACKER", "SAFE"}

# Domains to never classify
SKIP_DOMAINS = {
    "pi.hole", "localhost", "local", "lan",
    "google.com", "cloudflare.com", "apple.com",
    "microsoft.com", "github.com",
}
SKIP_TLDS = {".local", ".lan", ".arpa", ".internal"}

# Threat intel feeds
THREAT_INTEL_FEEDS = [
    {
        "name": "Feodo C2 Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/domainblocklist.txt",
        "comment_prefix": "#",
        "category": "C2",
    },
    {
        "name": "URLhaus Malware",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "comment_prefix": "#",
        "category": "MALWARE",
    },
    {
        "name": "DigitalSide OSINT",
        "url": "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
        "comment_prefix": "#",
        "category": "MALWARE",
    },
    {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "comment_prefix": "#",
        "category": "PHISHING",
        "is_url_list": True,
    },
]

THREAT_INTEL_INTERVAL_HOURS = 6
LOG_LEVEL = "INFO"

# Paths — can be overridden by config_local.py
BASE_DIR = os.path.expanduser("~/pihole-ai")
STATE_DB_PATH = os.path.join(BASE_DIR, "state.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
PIHOLE_DB_PATH = "/etc/pihole/gravity.db"
FTL_LOG_PATH = "/var/log/pihole/pihole.log"
