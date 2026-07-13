# Static defaults — overridden by config_local.py for user-specific values
import os

# Ollama
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_MODEL = "granite4.1:3b"
OLLAMA_CONNECT_TIMEOUT = 5
OLLAMA_READ_TIMEOUT = 120
OLLAMA_MAX_RETRIES = 2   # total attempts
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
TI_BLOCK_EXPIRY_DAYS = 30      # unblock TI: feed domains not re-seen in this many days (0 = never expire)
DB_RETENTION_DAYS = 90         # prune classification/sync/cache history older than this
DB_PRUNE_INTERVAL_HOURS = 24   # how often the syncer runs the prune

# ── Shared hosting / user-content platforms ──────────────────────────────────
# Primary source is the PSL private-domains section (synced weekly into StateDB,
# offline fallback = tldextract bundled snapshot). A feed hostname under one of
# these suffixes is attacker-controlled user content: block the FULL hostname
# and ignore the provider's popularity.
PSL_FEED_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
PSL_FEED_NAME = "psl-private-domains"
PSL_SYNC_INTERVAL_HOURS = 168        # weekly, like the Tranco list
SHARED_HOSTING_REFRESH_SECONDS = 3600  # in-memory suffix cache TTL
SHARED_HOSTING_WEIGHT = 10           # rule weight: hostname is user content on a shared host

# ── DNS/ASN reputation ────────────────────────────────────────────────────────
# Domains that resolve into a Spamhaus ASN-DROP network (hijacked or
# criminal-run ASNs) get a strong rule-score signal. Lookups run only on the
# watcher LLM path (post-prefilter, low volume) and always fail open.
ASN_REPUTATION_ENABLED = True
ASN_DROP_FEED_URL = "https://www.spamhaus.org/drop/asndrop.json"
ASN_DROP_FEED_NAME = "spamhaus-asn-drop"
ASN_SYNC_INTERVAL_HOURS = 24
UPSTREAM_DNS_SERVER = "1.1.1.1"  # resolve directly upstream, never through Pi-hole (loop)
ASN_LOOKUP_TIMEOUT = 3           # seconds, per DNS query
ASN_CACHE_DAYS = 7               # domain→ASN cache TTL (hosting moves, positives expire too)
ASN_DROP_WEIGHT = 60             # rule weight: domain hosted in a DROP-listed ASN

# ── TLS certificate analysis ──────────────────────────────────────────────────
# OPT-IN ONLY: fetching a certificate opens a TCP connection to the suspected
# malicious host from this machine's IP. Runs only on the watcher LLM path.
TLS_ANALYSIS_ENABLED = False
TLS_TIMEOUT = 4                  # seconds, per handshake
TLS_CACHE_DAYS = 7               # domain→cert cache TTL (successes and failures)
TLS_INVALID_WEIGHT = 20          # rule weight: certificate failed verification
TLS_NEW_CERT_DAYS = 14           # certs younger than this add TLS_NEW_CERT_WEIGHT
TLS_NEW_CERT_WEIGHT = 10         # weak signal — Let's Encrypt rotates every ~60-90d
# User seed for providers the PSL private section does not (yet) list.
# Same pattern as EXTRA_BRANDS: data-driven primary source + small local seed.
EXTRA_SHARED_HOSTING_SUFFIXES = {
    "weebly.com",
    "weeblysite.com",
    "webflow.io",
    "godaddysites.com",
    "replit.app",
    "gitbook.io",
    "zapier.app",
    "edgeone.app",
    "myclickfunnels.com",
    "eu.cc",
}
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

# RDAP domain age scoring — registration date lookup for domains that reach
# the LLM path (post pre-filter, low volume). Cached in StateDB; failures are
# fail-open (no score). Feeds are never RDAP-checked (40k+ entries).
RDAP_ENABLED = True
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
RDAP_TIMEOUT = 10
RDAP_NEGATIVE_CACHE_DAYS = 7   # retry failed lookups after this many days
DOMAIN_AGE_NEW_DAYS = 30       # domain younger than this: strong signal
DOMAIN_AGE_NEW_WEIGHT = 25
DOMAIN_AGE_RECENT_DAYS = 180   # domain younger than this: weak signal
DOMAIN_AGE_RECENT_WEIGHT = 10

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
