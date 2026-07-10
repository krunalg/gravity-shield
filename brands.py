from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging

from features.lexical import hostname

logger = logging.getLogger(__name__)


def derive_brand_map(ranked_domains: dict[str, int],
                     max_rank: int = BRAND_SOURCE_RANK_THRESHOLD,
                     min_token_length: int = BRAND_MIN_TOKEN_LENGTH,
                     extra: dict[str, str] | None = None) -> dict[str, str]:
    """Build {brand_token: official_apex} from a popularity-ranked domain map.

    The brand token is the SLD of the apex (e.g. "google" for google.com).
    Tokens shorter than min_token_length are dropped — they cause fuzzy
    false positives. When two apexes share a token, the better-ranked apex
    wins. `extra` entries (user seed) always override derived ones.
    """
    brands: dict[str, str] = {}
    for apex, rank in sorted(ranked_domains.items(), key=lambda kv: kv[1]):
        if rank > max_rank:
            continue
        token = hostname(apex)
        if len(token) < min_token_length:
            continue
        brands.setdefault(token, apex)
    if extra:
        brands.update(extra)
    return brands


def get_brand_map(state_db) -> dict[str, str]:
    """Brand map derived from the StateDB Tranco snapshot, merged with
    EXTRA_BRANDS. Falls back to EXTRA_BRANDS alone if the DB is unavailable."""
    try:
        ranked = state_db.get_top_domains(BRAND_SOURCE_RANK_THRESHOLD)
        return derive_brand_map(ranked, extra=EXTRA_BRANDS)
    except Exception as e:
        logger.warning(f"Brand map derivation failed ({e}) — using EXTRA_BRANDS only")
        return dict(EXTRA_BRANDS)
