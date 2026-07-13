import os, sys, ssl
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import tls_cert
from tls_cert import parse_cert, get_cert_info

# ssl.getpeercert() shape for a verified certificate
CERT_SAMPLE = {
    "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),),
               (("commonName", "R11"),)),
    "subject": ((("commonName", "evil.example"),),),
    "notBefore": "Jun  1 00:00:00 2026 GMT",
    "notAfter": "Aug 30 00:00:00 2026 GMT",
    "subjectAltName": (("DNS", "evil.example"), ("DNS", "www.evil.example")),
}


def test_parse_cert_extracts_issuer_age_and_sans():
    info = parse_cert(CERT_SAMPLE)
    assert info["issuer"] == "Let's Encrypt"
    assert info["san_count"] == 2
    assert info["verify_failed"] is False
    assert info["not_before"] == "2026-06-01T00:00:00+00:00"


def test_fetch_cert_info_verify_failure_is_a_signal():
    with patch("tls_cert._resolve_addr", return_value="93.184.216.34"), \
         patch("tls_cert._handshake",
               side_effect=ssl.SSLCertVerificationError("self-signed certificate")):
        info = tls_cert.fetch_cert_info("selfsigned.example")
    assert info["verify_failed"] is True
    assert "self-signed" in info["fail_reason"]


def test_fetch_cert_info_connection_failure_returns_none():
    with patch("tls_cert._resolve_addr", return_value="93.184.216.34"), \
         patch("tls_cert._handshake", side_effect=OSError("connection refused")):
        assert tls_cert.fetch_cert_info("dead.example") is None


def test_get_cert_info_uses_fresh_cache():
    state = MagicMock()
    state.get_domain_tls.return_value = {
        "info": {"issuer": "X", "san_count": 1, "verify_failed": False,
                 "fail_reason": None, "not_before": "2026-06-01T00:00:00+00:00"},
        "fetched_at": "2999-01-01T00:00:00+00:00",
    }
    with patch("tls_cert.fetch_cert_info") as fetch:
        info = get_cert_info("cached.example", state)
    fetch.assert_not_called()
    assert info["issuer"] == "X"
    assert isinstance(info["cert_age_days"], int)


def test_get_cert_info_negative_cache_returns_none_without_fetch():
    state = MagicMock()
    state.get_domain_tls.return_value = {
        "info": None, "fetched_at": "2999-01-01T00:00:00+00:00",
    }
    with patch("tls_cert.fetch_cert_info") as fetch:
        assert get_cert_info("dead.example", state) is None
    fetch.assert_not_called()


def test_get_cert_info_stale_cache_refetches_and_recaches():
    state = MagicMock()
    state.get_domain_tls.return_value = {
        "info": None, "fetched_at": "2020-01-01T00:00:00+00:00",
    }
    fresh = {"issuer": "Y", "san_count": 1, "verify_failed": False,
             "fail_reason": None, "not_before": None}
    with patch("tls_cert.fetch_cert_info", return_value=fresh):
        info = get_cert_info("stale.example", state)
    assert info["issuer"] == "Y"
    assert info["cert_age_days"] is None
    state.cache_domain_tls.assert_called_once_with("stale.example", fresh)


def test_get_cert_info_fetch_failure_is_negative_cached():
    state = MagicMock()
    state.get_domain_tls.return_value = None
    with patch("tls_cert.fetch_cert_info", return_value=None):
        assert get_cert_info("dead.example", state) is None
    state.cache_domain_tls.assert_called_once_with("dead.example", None)


def test_fetch_cert_info_refuses_private_ips():
    """Prevents the daemon being used to probe LAN hosts via crafted DNS names."""
    with patch("tls_cert._resolve_addr", return_value="192.168.1.50"), \
         patch("tls_cert._handshake") as handshake:
        assert tls_cert.fetch_cert_info("internal.example") is None
    handshake.assert_not_called()


def test_fetch_cert_info_allows_public_ips():
    with patch("tls_cert._resolve_addr", return_value="93.184.216.34"), \
         patch("tls_cert._handshake", return_value=CERT_SAMPLE):
        info = tls_cert.fetch_cert_info("evil.example")
    assert info["issuer"] == "Let's Encrypt"
