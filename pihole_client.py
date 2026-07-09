from config import *
try:
    from config_local import *
except ImportError:
    pass

import re
import shlex
import sqlite3
import subprocess
import threading
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
    def __init__(self,
                 db_path: str = PIHOLE_DB_PATH,
                 reload_cmd: Optional[str] = PIHOLE_RELOAD_CMD,
                 reload_interval_seconds: int = PIHOLE_RELOAD_INTERVAL_SECONDS):
        self._db_path = db_path
        self._reload_cmd = reload_cmd
        self._reload_interval_seconds = reload_interval_seconds
        self._reload_lock = threading.Lock()
        self._reload_timer: Optional[threading.Timer] = None

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
            self._schedule_reload()
        return added

    def flush_reload(self):
        with self._reload_lock:
            timer = self._reload_timer
            self._reload_timer = None
        if timer:
            timer.cancel()
            self._reload()

    def _schedule_reload(self):
        if not self._reload_cmd:
            return
        if self._reload_interval_seconds <= 0:
            self._reload()
            return

        with self._reload_lock:
            if self._reload_timer and self._reload_timer.is_alive():
                logger.debug("Pi-hole list reload already scheduled")
                return
            timer = threading.Timer(self._reload_interval_seconds, self._run_scheduled_reload)
            timer.daemon = True
            self._reload_timer = timer
            timer.start()
        logger.info(f"Scheduled Pi-hole list reload in {self._reload_interval_seconds}s")

    def _run_scheduled_reload(self):
        with self._reload_lock:
            self._reload_timer = None
        self._reload()

    def _reload(self):
        if not self._reload_cmd:
            return
        try:
            result = subprocess.run(
                shlex.split(self._reload_cmd),
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                logger.warning(f"{self._reload_cmd} returned {result.returncode}: {result.stderr}")
            else:
                logger.debug("Pi-hole lists reloaded")
        except Exception as e:
            logger.error(f"Failed to reload Pi-hole: {e}")
