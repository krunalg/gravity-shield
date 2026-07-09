# Static defaults — overridden by config_local.py for user-specific values
import os

# Ollama
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "granite4.1:3b"
OLLAMA_TIMEOUT = 30
OLLAMA_MAX_RETRIES = 2

# Classifier thresholds
BLOCK_CONFIDENCE_THRESHOLD = 0.80
CATEGORIES_TO_BLOCK = {"MALWARE", "PHISHING", "C2", "RANSOMWARE"}
CATEGORIES_SAFE = {"AD", "TRACKER", "SAFE"}
DGA_THRESHOLD = 0.70
ENTROPY_THRESHOLD = 3.8
RULE_SCORE_THRESHOLD = 70
BRAND_MATCH_THRESHOLD = 0.80
PUNYCODE_WEIGHT = 35
HIGH_RISK_TLDS = {".ru", ".xyz", ".tk", ".pw", ".cc", ".top", ".click", ".info"}
KNOWN_BRANDS = {
    "google": "google.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "github": "github.com",
    "cloudflare": "cloudflare.com",
    "meta": "meta.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "openai": "openai.com",
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "sbi": "sbi.co.in",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
}

# Domains to never classify or block
SKIP_DOMAINS = {
    "pi.hole", "localhost", "local", "lan",
    "google.com", "cloudflare.com", "apple.com",
    "microsoft.com", "github.com",
    "instagram.c10r.instagram.com",
}
SKIP_DOMAIN_SUFFIXES = {
    ".facebook.com", ".fbcdn.net", ".instagram.com",
    ".messenger.com", ".meta.com", ".whatsapp.com",
}
NEVER_BLOCK_DOMAINS = SKIP_DOMAINS
NEVER_BLOCK_SUFFIXES = SKIP_DOMAIN_SUFFIXES
SKIP_TLDS = {".local", ".lan", ".arpa", ".internal"}

# Threat intel feeds
THREAT_INTEL_FEEDS = [
    {
        "name": "URLhaus",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
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
PIHOLE_RELOAD_CMD = "sudo -n pihole reloadlists"
PIHOLE_RELOAD_INTERVAL_SECONDS = 60
PIHOLE_BLOCK_GROUP_NAME = "Adaptive Threat Blocklist"
