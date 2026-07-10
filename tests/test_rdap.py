import os, sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import rdap


_BOOTSTRAP_DOC = {
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
        [["xyz"], ["http://insecure.example/", "https://rdap.nic.xyz/"]],
    ]
}


def test_parse_bootstrap_maps_tld_to_https_base():
    mapping = rdap.parse_bootstrap(_BOOTSTRAP_DOC)
    assert mapping["com"] == "https://rdap.verisign.com/com/v1"
    assert mapping["net"] == "https://rdap.verisign.com/com/v1"
    assert mapping["xyz"] == "https://rdap.nic.xyz"  # prefers https


def test_parse_registration_date_extracts_registration_event():
    doc = {"events": [
        {"eventAction": "last changed", "eventDate": "2024-05-01T00:00:00Z"},
        {"eventAction": "registration", "eventDate": "2020-01-15T09:30:00Z"},
    ]}
    assert rdap.parse_registration_date(doc) == "2020-01-15T09:30:00Z"


def test_parse_registration_date_none_when_missing():
    assert rdap.parse_registration_date({"events": []}) is None
    assert rdap.parse_registration_date({}) is None


def test_get_domain_age_days_uses_cached_creation_date():
    state = MagicMock()
    created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    state.get_domain_registration.return_value = {
        "created_at": created, "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    with patch("rdap.fetch_registration_date") as fetch:
        age = rdap.get_domain_age_days("evil.com", state)
    fetch.assert_not_called()
    assert age == 10


def test_get_domain_age_days_fetches_and_caches_on_miss():
    state = MagicMock()
    state.get_domain_registration.return_value = None
    created = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    with patch("rdap.fetch_registration_date", return_value=created) as fetch:
        age = rdap.get_domain_age_days("evil.com", state)
    fetch.assert_called_once_with("evil.com")
    state.cache_domain_registration.assert_called_once_with("evil.com", created)
    assert age == 3


def test_get_domain_age_days_negative_cache_prevents_requery():
    state = MagicMock()
    state.get_domain_registration.return_value = {
        "created_at": None,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    with patch("rdap.fetch_registration_date") as fetch:
        age = rdap.get_domain_age_days("evil.com", state)
    fetch.assert_not_called()
    assert age is None


def test_get_domain_age_days_negative_cache_expires():
    state = MagicMock()
    stale = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    state.get_domain_registration.return_value = {"created_at": None, "fetched_at": stale}
    created = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    with patch("rdap.fetch_registration_date", return_value=created) as fetch:
        age = rdap.get_domain_age_days("evil.com", state)
    fetch.assert_called_once()
    assert age == 400


def test_failed_lookup_is_negative_cached():
    state = MagicMock()
    state.get_domain_registration.return_value = None
    with patch("rdap.fetch_registration_date", return_value=None):
        age = rdap.get_domain_age_days("evil.com", state)
    state.cache_domain_registration.assert_called_once_with("evil.com", None)
    assert age is None


def test_fetch_registration_date_no_server_for_tld():
    with patch("rdap._bootstrap_map", return_value={"com": "https://rdap.example"}):
        assert rdap.fetch_registration_date("evil.internal") is None


def test_unparseable_creation_date_returns_none():
    state = MagicMock()
    state.get_domain_registration.return_value = {
        "created_at": "not-a-date", "fetched_at": datetime.now(timezone.utc).isoformat(),
    }
    assert rdap.get_domain_age_days("evil.com", state) is None
