from config import *
try:
    from config_local import *
except ImportError:
    pass

import ipaddress
import logging
import socket
import ssl
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _resolve_addr(domain: str) -> str:
    """First resolved address for the domain's TLS endpoint."""
    infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
    return infos[0][4][0]


def _handshake(domain: str) -> dict:
    """Verified TLS handshake; returns ssl.getpeercert() dict.

    Raises ssl.SSLCertVerificationError on an invalid certificate and
    OSError-family exceptions when the host is unreachable or has no TLS.
    """
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=TLS_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
            return tls_sock.getpeercert()


def parse_cert(cert: dict) -> dict:
    """Distil an ssl.getpeercert() dict into the fields the pipeline uses."""
    issuer = None
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key == "organizationName":
                issuer = value
    not_before = None
    if cert.get("notBefore"):
        try:
            seconds = ssl.cert_time_to_seconds(cert["notBefore"])
            not_before = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
        except ValueError:
            logger.debug(f"Unparseable notBefore: {cert['notBefore']!r}")
    return {
        "issuer": issuer,
        "san_count": len(cert.get("subjectAltName", ())),
        "verify_failed": False,
        "fail_reason": None,
        "not_before": not_before,
    }


def fetch_cert_info(domain: str) -> dict | None:
    """Fetch and parse the domain's TLS certificate.

    A failed verification (self-signed, expired, hostname mismatch) is a
    signal and returns a verify_failed dict; an unreachable host or a host
    without TLS is no signal and returns None.
    """
    try:
        # Never handshake with non-global addresses: a crafted DNS name must
        # not turn the daemon into a LAN port prober.
        addr = ipaddress.ip_address(_resolve_addr(domain))
        if not addr.is_global:
            logger.debug(f"TLS fetch refused for {domain}: resolves to non-global {addr}")
            return None
    except Exception as e:
        logger.debug(f"TLS resolution failed for {domain}: {e}")
        return None
    try:
        cert = _handshake(domain)
    except ssl.SSLCertVerificationError as e:
        reason = getattr(e, "verify_message", None) or str(e)
        logger.debug(f"TLS verification failed for {domain}: {reason}")
        return {
            "issuer": None,
            "san_count": 0,
            "verify_failed": True,
            "fail_reason": reason,
            "not_before": None,
        }
    except Exception as e:
        logger.debug(f"TLS fetch failed for {domain}: {e}")
        return None
    return parse_cert(cert)


def _cert_age_days(not_before: str | None) -> int | None:
    if not not_before:
        return None
    try:
        issued = datetime.fromisoformat(not_before)
        if issued.tzinfo is None:
            issued = issued.replace(tzinfo=timezone.utc)
        return max((datetime.now(timezone.utc) - issued).days, 0)
    except ValueError:
        return None


def get_cert_info(domain: str, state_db) -> dict | None:
    """Certificate info for the domain, from StateDB cache or a live handshake.

    Results (including failures) are cached for TLS_CACHE_DAYS. cert_age_days
    is recomputed from the stored notBefore on every call. Returns None when
    there is no TLS signal — callers must treat that as "no signal".

    NOTE: a live fetch connects to the (possibly malicious) host from this
    machine's IP — that is why TLS_ANALYSIS_ENABLED defaults to off.
    """
    cached = state_db.get_domain_tls(domain)
    info = None
    if cached is not None:
        fetched = datetime.fromisoformat(cached["fetched_at"])
        if fetched.tzinfo is None:
            fetched = fetched.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - fetched).days < TLS_CACHE_DAYS:
            info = cached["info"]
            if info is None:
                return None  # negative cache still fresh
        else:
            cached = None
    if cached is None:
        info = fetch_cert_info(domain)
        state_db.cache_domain_tls(domain, info)
        if info is None:
            return None
    return {**info, "cert_age_days": _cert_age_days(info.get("not_before"))}
