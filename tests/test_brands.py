import os, sys
from unittest.mock import MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from brands import derive_brand_map, get_brand_map


def test_derive_brand_map_uses_sld_as_token_and_apex_as_official():
    ranks = {"google.com": 1, "paypal.com": 60}
    brands = derive_brand_map(ranks, max_rank=1000, min_token_length=5)
    assert brands == {"google": "google.com", "paypal": "paypal.com"}


def test_derive_brand_map_filters_short_tokens():
    ranks = {"t.co": 20, "qq.com": 30, "vk.com": 40, "github.com": 50}
    brands = derive_brand_map(ranks, max_rank=1000, min_token_length=5)
    assert brands == {"github": "github.com"}


def test_derive_brand_map_respects_rank_threshold():
    ranks = {"google.com": 1, "obscure-site.com": 5000}
    brands = derive_brand_map(ranks, max_rank=1000, min_token_length=5)
    assert "obscure-site" not in brands
    assert brands["google"] == "google.com"


def test_derive_brand_map_multi_part_tld_uses_sld():
    ranks = {"amazon.co.uk": 80}
    brands = derive_brand_map(ranks, max_rank=1000, min_token_length=5)
    assert brands == {"amazon": "amazon.co.uk"}


def test_derive_brand_map_duplicate_token_keeps_best_ranked_apex():
    ranks = {"google.com": 1, "google.co.in": 500}
    brands = derive_brand_map(ranks, max_rank=1000, min_token_length=5)
    assert brands == {"google": "google.com"}


def test_derive_brand_map_extra_brands_override_and_extend():
    ranks = {"google.com": 1}
    brands = derive_brand_map(
        ranks, max_rank=1000, min_token_length=5,
        extra={"icici": "icicibank.com", "google": "google.co.in"},
    )
    assert brands["icici"] == "icicibank.com"
    assert brands["google"] == "google.co.in"  # explicit user seed wins


def test_get_brand_map_reads_top_domains_from_state_db():
    state = MagicMock()
    state.get_top_domains.return_value = {"paypal.com": 30}
    brands = get_brand_map(state)
    assert brands["paypal"] == "paypal.com"


def test_get_brand_map_falls_back_to_extra_brands_on_db_error():
    state = MagicMock()
    state.get_top_domains.side_effect = RuntimeError("db locked")
    brands = get_brand_map(state)
    import config
    assert brands == config.EXTRA_BRANDS
