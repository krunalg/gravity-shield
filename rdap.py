from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger(__name__)

_BOOTSTRAP_REFRESH_SECONDS = 7 * 24 * 3600
_bootstrap_cache: dict = {"fetched_at": 0.0, "map": {}}


def _bootstrap_map() -> dict[str, str]:
    """TLD → RDAP base URL from the IANA bootstrap registry, cached in memory."""
    now = time.time()
    if _bootstrap_cache["map"] and now - _bootstrap_cache["fetched_at"] < _BOOTSTRAP_REFRESH_SECONDS:
        return _bootstrap_cache["map"]
    try:
        resp = requests.get(RDAP_BOOTSTRAP_URL, timeout=RDAP_TIMEOUT,
                            headers={"User-Agent": "pihole-ai-guardian/1.0"})
        resp.raise_for_status()
        mapping = parse_bootstrap(resp.json())
        _bootstrap_cache.update(fetched_at=now, map=mapping)
    except Exception as e:
        logger.warning(f"RDAP bootstrap fetch failed: {e} — keeping cached map "
                       f"({len(_bootstrap_cache['map'])} TLDs)")
    return _bootstrap_cache["map"]


def parse_bootstrap(data: dict) -> dict[str, str]:
    """Parse the IANA dns.json bootstrap document into {tld: base_url}."""
    mapping: dict[str, str] = {}
    for tlds, urls in data.get("services", []):
        base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
        if not base:
            continue
        for tld in tlds:
            mapping[tld.lower()] = base.rstrip("/")
    return mapping


def parse_registration_date(rdap_response: dict) -> str | None:
    """Extract the registration eventDate (ISO string) from an RDAP domain object."""
    for event in rdap_response.get("events", []):
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            return event["eventDate"]
    return None


def fetch_registration_date(apex: str) -> str | None:
    """Query RDAP for the apex domain's registration date. None on any failure."""
    tld = apex.rsplit(".", 1)[-1]
    base = _bootstrap_map().get(tld)
    if not base:
        logger.debug(f"RDAP: no server for TLD .{tld}")
        return None
    try:
        resp = requests.get(f"{base}/domain/{apex}", timeout=RDAP_TIMEOUT,
                            headers={"User-Agent": "pihole-ai-guardian/1.0",
                                     "Accept": "application/rdap+json"})
        if resp.status_code == 404:
            logger.debug(f"RDAP: {apex} not found")
            return None
        resp.raise_for_status()
        return parse_registration_date(resp.json())
    except Exception as e:
        logger.warning(f"RDAP lookup failed for {apex}: {e}")
        return None


def _age_days(created_iso: str) -> int | None:
    try:
        created = datetime.fromisoformat(created_iso.replace("Z", "+00:00"))
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - created).days, 0)
    except ValueError:
        logger.warning(f"RDAP: unparseable registration date {created_iso!r}")
        return None


def get_domain_age_days(apex: str, state_db) -> int | None:
    """Age of the apex domain in days, from StateDB cache or a live RDAP query.

    Successful lookups are cached forever (registration date never changes);
    failures are negative-cached for RDAP_NEGATIVE_CACHE_DAYS. Returns None
    when the age is unknown — callers must treat that as "no signal".
    """
    cached = state_db.get_domain_registration(apex)
    if cached is not None:
        if cached["created_at"] is not None:
            return _age_days(cached["created_at"])
        fetched = datetime.fromisoformat(cached["fetched_at"])
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - fetched).days < RDAP_NEGATIVE_CACHE_DAYS:
            return None  # negative cache still fresh — don't re-query

    created = fetch_registration_date(apex)
    state_db.cache_domain_registration(apex, created)
    if created is None:
        return None
    return _age_days(created)
