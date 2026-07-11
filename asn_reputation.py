from config import *
try:
    from config_local import *
except ImportError:
    pass

import json
import logging
from datetime import datetime, timezone

import dns.resolver
import requests

logger = logging.getLogger(__name__)


def parse_asn_drop(text: str) -> set[int]:
    """Parse the Spamhaus ASN-DROP JSONL feed into a set of ASNs.

    Each line is a JSON object; entries carry an integer `asn`, the trailing
    metadata record does not.
    """
    asns: set[int] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        asn = obj.get("asn")
        if isinstance(asn, int):
            asns.add(asn)
    return asns


def fetch_asn_drop() -> set[int]:
    """Fetch the Spamhaus ASN-DROP feed. Empty set on any error."""
    try:
        resp = requests.get(ASN_DROP_FEED_URL, timeout=30,
                            headers={"User-Agent": "pihole-ai-guardian/1.0"})
        resp.raise_for_status()
        return parse_asn_drop(resp.text)
    except Exception as e:
        logger.warning(f"ASN-DROP fetch failed: {e}")
        return set()


def _resolver() -> "dns.resolver.Resolver":
    # Query the upstream resolver directly, not Pi-hole: the daemon's own
    # lookups must not loop back into the log it is tailing.
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [UPSTREAM_DNS_SERVER]
    resolver.timeout = ASN_LOOKUP_TIMEOUT
    resolver.lifetime = ASN_LOOKUP_TIMEOUT
    return resolver


def resolve_ip(domain: str) -> str | None:
    """First A record of the domain via the upstream resolver. None on failure."""
    try:
        answers = _resolver().resolve(domain, "A")
        return answers[0].to_text()
    except Exception as e:
        logger.debug(f"A lookup failed for {domain}: {e}")
        return None


def parse_cymru_txt(txt: str) -> int | None:
    """Origin ASN from a Team Cymru TXT record: '13335 | 1.1.1.0/24 | US | ...'.

    The first field may list several origin ASNs — the first one is used.
    """
    first_field = txt.strip().strip('"').split("|")[0].strip()
    if not first_field:
        return None
    token = first_field.split()[0]
    return int(token) if token.isdigit() else None


def ip_to_asn(ip: str) -> int | None:
    """Origin ASN for an IPv4 address via Team Cymru's DNS interface."""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        answers = _resolver().resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT")
        for record in answers:
            asn = parse_cymru_txt(record.to_text())
            if asn is not None:
                return asn
    except Exception as e:
        logger.debug(f"ASN lookup failed for {ip}: {e}")
    return None


def get_domain_asn(domain: str, state_db) -> int | None:
    """ASN currently hosting the domain, from StateDB cache or live lookups.

    Both successes and failures are cached for ASN_CACHE_DAYS (hosting moves,
    so positive results expire too). Returns None when unknown — callers must
    treat that as "no signal".
    """
    cached = state_db.get_domain_asn(domain)
    if cached is not None:
        fetched = datetime.fromisoformat(cached["fetched_at"])
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - fetched).days < ASN_CACHE_DAYS:
            return cached["asn"]

    ip = resolve_ip(domain)
    asn = ip_to_asn(ip) if ip else None
    state_db.cache_domain_asn(domain, asn)
    return asn
