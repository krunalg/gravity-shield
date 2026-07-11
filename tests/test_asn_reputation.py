import os, sys
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import asn_reputation
from asn_reputation import (
    parse_asn_drop,
    parse_cymru_txt,
    get_domain_asn,
)

ASN_DROP_SAMPLE = """\
{"asn":205112,"rir":"ripe","domain":"badhost.example","cc":"RU"}
{"asn":401199,"rir":"arin","domain":"bullet.example","cc":"US"}
{"type":"metadata","timestamp":1720000000,"size":2}
not json at all
"""


def test_parse_asn_drop_extracts_asns_and_skips_metadata():
    asns = parse_asn_drop(ASN_DROP_SAMPLE)
    assert asns == {205112, 401199}


def test_parse_asn_drop_empty_on_garbage():
    assert parse_asn_drop("garbage\n\n") == set()


def test_parse_cymru_txt_single_asn():
    assert parse_cymru_txt('"13335 | 1.1.1.0/24 | US | apnic | 2011-08-11"') == 13335


def test_parse_cymru_txt_multiple_origin_asns_takes_first():
    assert parse_cymru_txt('"13335 7018 | 1.1.1.0/24 | US | apnic |"') == 13335


def test_parse_cymru_txt_garbage_returns_none():
    assert parse_cymru_txt('"| no asn here |"') is None


def test_get_domain_asn_uses_fresh_cache():
    state = MagicMock()
    state.get_domain_asn.return_value = {
        "asn": 13335, "fetched_at": "2999-01-01T00:00:00+00:00"
    }
    with patch("asn_reputation.resolve_ip") as resolve:
        assert get_domain_asn("cached.example", state) == 13335
    resolve.assert_not_called()


def test_get_domain_asn_negative_cache_returns_none_without_lookup():
    state = MagicMock()
    state.get_domain_asn.return_value = {
        "asn": None, "fetched_at": "2999-01-01T00:00:00+00:00"
    }
    with patch("asn_reputation.resolve_ip") as resolve:
        assert get_domain_asn("unknown.example", state) is None
    resolve.assert_not_called()


def test_get_domain_asn_stale_cache_triggers_lookup_and_recache():
    state = MagicMock()
    state.get_domain_asn.return_value = {
        "asn": 13335, "fetched_at": "2020-01-01T00:00:00+00:00"
    }
    with patch("asn_reputation.resolve_ip", return_value="1.2.3.4"), \
         patch("asn_reputation.ip_to_asn", return_value=205112):
        assert get_domain_asn("stale.example", state) == 205112
    state.cache_domain_asn.assert_called_once_with("stale.example", 205112)


def test_get_domain_asn_resolution_failure_is_negative_cached():
    state = MagicMock()
    state.get_domain_asn.return_value = None
    with patch("asn_reputation.resolve_ip", return_value=None):
        assert get_domain_asn("dead.example", state) is None
    state.cache_domain_asn.assert_called_once_with("dead.example", None)


def test_fetch_asn_drop_empty_on_network_error():
    with patch("asn_reputation.requests.get", side_effect=RuntimeError("net down")):
        assert asn_reputation.fetch_asn_drop() == set()
