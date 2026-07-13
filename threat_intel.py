from config import *
try:
    from config_local import *
except ImportError:
    pass

import ipaddress
import logging
import re
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HOSTS_PREFIX_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)")
_FETCH_TIMEOUT = 20


def parse_feed_content(content: str,
                       comment_prefix: str = "#",
                       is_url_list: bool = False) -> list[str]:
    """Extract bare domain names from a feed's text content."""
    domains = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if comment_prefix and line.startswith(comment_prefix):
            continue

        m = _HOSTS_PREFIX_RE.match(line)
        if m:
            line = m.group(1)

        if is_url_list and ("://" in line or line.startswith("http")):
            try:
                parsed = urlparse(line if "://" in line else f"http://{line}")
                # hostname strips port and credentials; netloc keeps them,
                # producing junk denylist rows like "evil.com:8080"
                line = parsed.hostname or parsed.path
            except Exception:
                continue

        domain = line.rstrip(".").lower()

        if _is_ip(domain):
            continue

        if "." not in domain or len(domain) < 4:
            continue

        if domain.endswith((".local", ".lan", ".internal", ".arpa")):
            continue

        domains.append(domain)

    return list(set(domains))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def fetch_feed(feed_cfg: dict) -> list[str]:
    """Fetch one feed URL and return parsed domain list. Returns [] on any error."""
    name = feed_cfg.get("name", feed_cfg["url"])
    is_json = feed_cfg.get("is_json", False)
    is_url_list = feed_cfg.get("is_url_list", False)
    comment_prefix = feed_cfg.get("comment_prefix", "#")

    try:
        logger.info(f"Fetching threat intel feed: {name}")
        resp = requests.get(feed_cfg["url"], timeout=_FETCH_TIMEOUT,
                            headers={"User-Agent": "pihole-ai-guardian/1.0"})
        resp.raise_for_status()

        if is_json:
            return _parse_json_feed(resp.json(), feed_cfg)

        return parse_feed_content(resp.text, comment_prefix=comment_prefix,
                                  is_url_list=is_url_list)

    except Exception as e:
        logger.error(f"Failed to fetch feed {name}: {e}")
        return []


def _parse_json_feed(data, feed_cfg: dict) -> list[str]:
    """Handle JSON feeds (e.g. PhishTank). Extracts URLs then pulls domains."""
    domains = []
    field = feed_cfg.get("json_domain_path", "url")
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and field in item:
                raw = item[field]
                try:
                    parsed = urlparse(raw)
                    if parsed.hostname:
                        domains.append(parsed.hostname.lower())
                except Exception:
                    pass
    return list(set(domains))
