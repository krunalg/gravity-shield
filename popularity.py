from config import *
try:
    from config_local import *
except ImportError:
    pass

import io
import logging
import zipfile

import requests

logger = logging.getLogger(__name__)

_FETCH_TIMEOUT = 60


def parse_top_list(text: str, max_rank: int = POPULARITY_RANK_THRESHOLD) -> dict[str, int]:
    """Parse a 'rank,domain' CSV (Tranco format) into {domain: rank}, capped at max_rank."""
    ranks: dict[str, int] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        rank_str, _, domain = line.partition(",")
        try:
            rank = int(rank_str)
        except ValueError:
            continue
        if rank > max_rank:
            continue
        domain = domain.strip().lower().rstrip(".")
        if "." not in domain:
            continue
        ranks[domain] = rank
    return ranks


def fetch_popularity_list(url: str = POPULARITY_FEED_URL,
                          max_rank: int = POPULARITY_RANK_THRESHOLD) -> dict[str, int]:
    """Fetch the popularity list (zip or plain CSV) and return {domain: rank}.
    Returns {} on any error."""
    try:
        logger.info(f"Fetching popularity list: {url}")
        resp = requests.get(url, timeout=_FETCH_TIMEOUT,
                            headers={"User-Agent": "pihole-ai-guardian/1.0"})
        resp.raise_for_status()
        content = resp.content
        if content[:2] == b"PK":  # zip magic
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                text = zf.read(zf.namelist()[0]).decode("utf-8", errors="replace")
        else:
            text = resp.text
        return parse_top_list(text, max_rank=max_rank)
    except Exception as e:
        logger.error(f"Failed to fetch popularity list {url}: {e}")
        return {}
