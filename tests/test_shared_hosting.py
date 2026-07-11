import os, sys
import pytest
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import shared_hosting
from shared_hosting import (
    parse_psl_private_suffixes,
    shared_hosting_provider,
    get_shared_hosting_suffixes,
)

PSL_SAMPLE = """\
// This Source Code Form is subject to the terms of the MPL
// ===BEGIN ICANN DOMAINS===
com
io
// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===
// GitHub : https://github.com
github.io
githubusercontent.com

// Cloudflare, Inc. : https://cloudflare.com
Pages.Dev
*.wildcard-host.example
!keep.wildcard-host.example
// ===END PRIVATE DOMAINS===
"""


@pytest.fixture(autouse=True)
def reset_suffix_cache():
    shared_hosting._SUFFIX_CACHE.update(loaded_at=0.0, suffixes=None)
    yield
    shared_hosting._SUFFIX_CACHE.update(loaded_at=0.0, suffixes=None)


def test_parse_psl_extracts_only_private_section():
    suffixes = parse_psl_private_suffixes(PSL_SAMPLE)
    assert "github.io" in suffixes
    assert "githubusercontent.com" in suffixes
    assert "com" not in suffixes
    assert "io" not in suffixes


def test_parse_psl_lowercases_and_handles_wildcards_and_exceptions():
    suffixes = parse_psl_private_suffixes(PSL_SAMPLE)
    assert "pages.dev" in suffixes
    assert "wildcard-host.example" in suffixes
    assert not any(s.startswith("!") or s.startswith("*") for s in suffixes)


def test_provider_match_subdomain():
    suffixes = {"github.io", "pages.dev"}
    assert shared_hosting_provider("evil.github.io", suffixes) == "github.io"
    assert shared_hosting_provider("a.b.pages.dev", suffixes) == "pages.dev"


def test_provider_match_case_insensitive():
    assert shared_hosting_provider("EVIL.GitHub.IO", {"github.io"}) == "github.io"


def test_provider_match_exact_apex():
    assert shared_hosting_provider("github.io", {"github.io"}) == "github.io"


def test_provider_no_match():
    assert shared_hosting_provider("www.google.com", {"github.io"}) is None
    # suffix must match on a label boundary, not substring
    assert shared_hosting_provider("evilgithub.io", {"github.io"}) is None


def test_get_suffixes_prefers_state_db():
    state = MagicMock()
    state.get_shared_hosting_suffixes.return_value = {"custom-host.example"}
    suffixes = get_shared_hosting_suffixes(state)
    assert "custom-host.example" in suffixes


def test_get_suffixes_falls_back_to_snapshot_when_db_empty():
    state = MagicMock()
    state.get_shared_hosting_suffixes.return_value = set()
    suffixes = get_shared_hosting_suffixes(state)
    # PSL private section in the bundled tldextract snapshot
    assert "github.io" in suffixes
    assert "pages.dev" in suffixes


def test_get_suffixes_falls_back_when_db_errors():
    state = MagicMock()
    state.get_shared_hosting_suffixes.side_effect = RuntimeError("db locked")
    suffixes = get_shared_hosting_suffixes(state)
    assert "github.io" in suffixes


def test_get_suffixes_merges_extra_config_seed():
    state = MagicMock()
    state.get_shared_hosting_suffixes.return_value = {"github.io"}
    with patch.object(shared_hosting, "EXTRA_SHARED_HOSTING_SUFFIXES", {"weebly.com"}):
        suffixes = get_shared_hosting_suffixes(state)
    assert "weebly.com" in suffixes
    assert "github.io" in suffixes


def test_fetch_psl_returns_empty_on_error():
    with patch("shared_hosting.requests.get", side_effect=RuntimeError("net down")):
        assert shared_hosting.fetch_psl_private_suffixes() == set()
