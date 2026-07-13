from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import time

import requests
import tldextract

logger = logging.getLogger(__name__)

# In-memory cache so the suffix set isn't rebuilt on every domain.
_SUFFIX_CACHE: dict = {"loaded_at": 0.0, "suffixes": None}

_PRIVATE_BEGIN = "===BEGIN PRIVATE DOMAINS==="
_PRIVATE_END = "===END PRIVATE DOMAINS==="


def parse_psl_private_suffixes(text: str) -> set[str]:
    """Extract the PRIVATE DOMAINS section of the Public Suffix List.

    Private-section entries are shared-hosting / user-content platforms
    (github.io, pages.dev, blogspot.com, ...) where each subdomain has a
    distinct, untrusted owner — exactly the set of providers whose popularity
    must not shield attacker subdomains.
    """
    suffixes: set[str] = set()
    in_private = False
    for line in text.splitlines():
        line = line.strip()
        if _PRIVATE_BEGIN in line:
            in_private = True
            continue
        if _PRIVATE_END in line:
            break
        if not in_private or not line or line.startswith("//"):
            continue
        if line.startswith("!"):
            continue  # exception rule — not a suffix
        if line.startswith("*."):
            line = line[2:]
        suffixes.add(line.lower())
    return suffixes


def fetch_psl_private_suffixes() -> set[str]:
    """Fetch the live PSL and return its private-section suffixes. Empty set on error."""
    try:
        resp = requests.get(PSL_FEED_URL, timeout=30,
                            headers={"User-Agent": "pihole-ai-guardian/1.0"})
        resp.raise_for_status()
        return parse_psl_private_suffixes(resp.text)
    except Exception as e:
        logger.warning(f"PSL fetch failed: {e}")
        return set()


def _snapshot_private_suffixes() -> set[str]:
    """Private suffixes from the tldextract bundled snapshot (offline fallback)."""
    with_private = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    icann_only = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)
    return set(with_private.tlds) - set(icann_only.tlds)


def invalidate_suffix_cache():
    """Drop the in-memory suffix cache — call after replacing the DB snapshot."""
    _SUFFIX_CACHE.update(loaded_at=0.0, suffixes=None)


def get_shared_hosting_suffixes(state_db=None) -> set[str]:
    """Shared-hosting suffix set: StateDB PSL snapshot, else bundled tldextract
    snapshot, always merged with the EXTRA_SHARED_HOSTING_SUFFIXES config seed."""
    now = time.time()
    if (_SUFFIX_CACHE["suffixes"] is not None
            and now - _SUFFIX_CACHE["loaded_at"] < SHARED_HOSTING_REFRESH_SECONDS):
        return _SUFFIX_CACHE["suffixes"]

    suffixes: set[str] = set()
    if state_db is not None:
        try:
            suffixes = set(state_db.get_shared_hosting_suffixes())
        except Exception as e:
            logger.warning(f"Shared-hosting suffixes unavailable from StateDB: {e}")
            suffixes = set()
    if not suffixes:
        suffixes = _snapshot_private_suffixes()
    suffixes |= {s.lower().lstrip(".") for s in EXTRA_SHARED_HOSTING_SUFFIXES}

    _SUFFIX_CACHE.update(loaded_at=now, suffixes=suffixes)
    return suffixes


def shared_hosting_provider(hostname: str, suffixes: set[str]) -> str | None:
    """Longest shared-hosting suffix matching hostname on a label boundary, or None."""
    host = hostname.rstrip(".").lower()
    labels = host.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate in suffixes:
            return candidate
    return None
