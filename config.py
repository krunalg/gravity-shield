# Static defaults — overridden by config_local.py for user-specific values
import os

# Ollama
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "granite4.1:3b"
OLLAMA_CONNECT_TIMEOUT = 5
OLLAMA_READ_TIMEOUT = 120
OLLAMA_TIMEOUT = OLLAMA_READ_TIMEOUT
OLLAMA_MAX_RETRIES = 2
OLLAMA_NUM_PREDICT = 256
OLLAMA_TEMPERATURE = 0.1

# Classifier thresholds
BLOCK_CONFIDENCE_THRESHOLD = 0.80
CATEGORIES_TO_BLOCK = {"MALWARE", "PHISHING", "C2", "RANSOMWARE"}
CATEGORIES_SAFE = {"AD", "TRACKER", "SAFE"}
DGA_THRESHOLD = 0.70
ENTROPY_THRESHOLD = 3.8
RULE_SCORE_THRESHOLD = 70      # syncer: min rule_score to block non-URLhaus feed domains
RULE_PREFILTER_THRESHOLD = 15  # skip Ollama if rule_score below this — auto-allow
BLOCK_RULE_SCORE_FLOOR = 15    # watcher: deterministic rule_score floor for LLM-driven blocks
SEEN_DOMAIN_TTL_DAYS = 7       # re-classify domains not seen in this many days
FEED_STALENESS_WARN_HOURS = 24 # warn if a feed hasn't synced in this many hours
BRAND_MATCH_THRESHOLD = 0.80
PUNYCODE_WEIGHT = 35
HIGH_RISK_TLDS = {".ru", ".xyz", ".tk", ".pw", ".cc", ".top", ".click", ".info"}
# Brand impersonation detection sources its brand list from the Tranco
# popularity list at runtime (see brands.py): every apex ranked within
# BRAND_SOURCE_RANK_THRESHOLD becomes a brand token (its SLD), provided the
# token is at least BRAND_MIN_TOKEN_LENGTH chars (shorter tokens cause fuzzy
# false positives). EXTRA_BRANDS is a user seed for targets below the rank
# cutoff (e.g. regional banks); its entries override derived ones.
BRAND_SOURCE_RANK_THRESHOLD = 1000
BRAND_MIN_TOKEN_LENGTH = 5
BRAND_MAP_REFRESH_SECONDS = 3600  # re-derive the brand map from StateDB hourly
EXTRA_BRANDS = {
    "hdfc": "hdfcbank.com",
    "icici": "icicibank.com",
    "sbi": "sbi.co.in",
    "claude": "claude.ai",
}

# Domains to never classify or block — infrastructure only. Established
# public domains are protected data-driven instead: the Tranco popularity
# allowlist (watcher) and the popular-apex feed guard (syncer).
SKIP_DOMAINS = {"pi.hole", "localhost", "local", "lan"}
SKIP_DOMAIN_SUFFIXES = {".local", ".lan", ".arpa", ".internal"}
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

# Popularity trust list (Tranco) — generic allowlist of established apex domains.
# Domains ranked within POPULARITY_RANK_THRESHOLD skip LLM classification unless
# they appear in a threat feed.
POPULARITY_FEED_NAME = "Tranco"
POPULARITY_FEED_URL = "https://tranco-list.eu/top-1m.csv.zip"
POPULARITY_RANK_THRESHOLD = 100_000
POPULARITY_SYNC_INTERVAL_HOURS = 168  # weekly
LOG_LEVEL = "INFO"

# Paths — can be overridden by config_local.py
BASE_DIR = os.path.expanduser("~/pihole-ai")
STATE_DB_PATH = os.path.join(BASE_DIR, "state.db")
# Optional user allowlist file — one entry per line; "domain.com" for an exact
# domain, ".domain.com" for a suffix (all subdomains). Feeds the never-block
# policy; edits are picked up without restarting the daemon. False-positive
# recovery path: add the wrongly blocked domain here, then remove it from the
# Adaptive Threat Blocklist group in Pi-hole.
USER_ALLOWLIST_PATH = os.path.join(BASE_DIR, "allowlist.txt")
LOG_DIR = os.path.join(BASE_DIR, "logs")
PIHOLE_DB_PATH = "/etc/pihole/gravity.db"
FTL_LOG_PATH = "/var/log/pihole/pihole.log"
PIHOLE_RELOAD_CMD = "sudo -n pihole reloadlists"
PIHOLE_RELOAD_INTERVAL_SECONDS = 60
PIHOLE_BLOCK_GROUP_NAME = "Adaptive Threat Blocklist"
