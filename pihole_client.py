from config import *
try:
    from config_local import *
except ImportError:
    pass

import re
import sqlite3
import subprocess
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

_QUERY_RE = re.compile(r"query\[(?:A|AAAA|MX|CNAME|TXT|HTTPS|SVCB)\]\s+(\S+)\s+from")
_SKIP_SUFFIXES = tuple(SKIP_TLDS) + (".arpa",)


def extract_domains_from_lines(lines: list[str]) -> list[str]:
    """Parse FTL log lines and return queried domain names, skipping internal/PTR."""
    domains = []
    for line in lines:
        m = _QUERY_RE.search(line)
        if not m:
            continue
        domain = m.group(1).rstrip(".").lower()
        if _should_skip(domain):
            continue
        domains.append(domain)
    return domains


def _should_skip(domain: str) -> bool:
    if not domain or "." not in domain:
        return True
    if domain.endswith(_SKIP_SUFFIXES):
        return True
    if domain in {"pi.hole", "localhost"}:
        return True
    return False


class PiholeClient:
    def __init__(self, db_path: str = PIHOLE_DB_PATH, reload_cmd: Optional[str] = "pihole reloadlists"):
        self._db_path = db_path
        self._reload_cmd = reload_cmd

    def add_to_denylist(self, domains: list[str], comment: str = "pihole-ai") -> int:
        """Insert domains into Pi-hole denylist (type=1). Returns count actually inserted."""
        if not domains:
            return 0
        now = int(time.time())
        conn = sqlite3.connect(self._db_path)
        added = 0
        try:
            for domain in domains:
                try:
                    conn.execute(
                        """INSERT INTO domainlist (domain, type, enabled, date_added, date_modified, comment)
                           VALUES (?,1,1,?,?,?)""",
                        (domain.lower(), now, now, comment)
                    )
                    added += 1
                except sqlite3.IntegrityError:
                    pass
            conn.commit()
        finally:
            conn.close()

        if added > 0:
            logger.info(f"Added {added} domains to Pi-hole denylist")
            self._reload()
        return added

    def _reload(self):
        if not self._reload_cmd:
            return
        try:
            result = subprocess.run(
                self._reload_cmd.split(),
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                logger.warning(f"pihole reloadlists returned {result.returncode}: {result.stderr}")
            else:
                logger.debug("Pi-hole lists reloaded")
        except Exception as e:
            logger.error(f"Failed to reload Pi-hole: {e}")
