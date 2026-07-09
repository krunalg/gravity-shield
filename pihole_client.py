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

from domain_policy import is_never_block_domain

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
                 reload_interval_seconds: int = PIHOLE_RELOAD_INTERVAL_SECONDS,
                 block_group_name: str = PIHOLE_BLOCK_GROUP_NAME):
        self._db_path = db_path
        self._reload_cmd = reload_cmd
        self._reload_interval_seconds = reload_interval_seconds
        self._block_group_name = block_group_name
        self._reload_lock = threading.Lock()
        self._reload_timer: Optional[threading.Timer] = None

    def add_to_denylist(self, domains: list[str], comment: str = "pihole-ai") -> int:
        """Insert domains into Pi-hole denylist (type=1). Returns count actually inserted."""
        if not domains:
            logger.debug("add_to_denylist called with empty domain list")
            return 0
        now = int(time.time())
        added = 0
        conn = None
        try:
            conn = sqlite3.connect(self._db_path)
            group_id = self._ensure_block_group(conn, now)
            logger.debug(f"Block group id: {group_id}")
            for domain in domains:
                domain = domain.lower()
                if is_never_block_domain(domain):
                    logger.info(f"Skipped never-block domain: {domain}")
                    continue
                try:
                    cur = conn.execute(
                        """INSERT INTO domainlist (domain, type, enabled, date_added, date_modified, comment)
                           VALUES (?,1,1,?,?,?)""",
                        (domain, now, now, comment)
                    )
                    domain_id = cur.lastrowid
                    logger.debug(f"Inserted domain '{domain}' with id={domain_id}")
                    self._assign_domain_to_group(conn, domain_id, group_id)
                    added += 1
                except sqlite3.IntegrityError:
                    domain_id = self._domainlist_id(conn, domain)
                    logger.debug(f"Domain '{domain}' already exists with id={domain_id}, assigning to group")
                    self._assign_domain_to_group(conn, domain_id, group_id)
            conn.commit()
            logger.info(f"Denylist transaction committed: {added} new domains added")
        except Exception as e:
            logger.error(f"Error while adding domains to denylist: {e}", exc_info=True)
        finally:
            if conn:
                conn.close()

        if added > 0:
            logger.info(f"Successfully added {added} domains to Pi-hole denylist and assigned to group '{self._block_group_name}'")
            self._schedule_reload()
        else:
            logger.debug("No new domains were added to denylist")
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

    def _ensure_block_group(self, conn: sqlite3.Connection, now: int) -> Optional[int]:
        if not self._table_exists(conn, "group"):
            logger.warning("'group' table not found in Pi-hole DB — group assignment skipped")
            return None
        if not self._table_exists(conn, "domainlist_by_group"):
            logger.warning("'domainlist_by_group' table not found in Pi-hole DB — group assignment skipped")
            return None
        row = conn.execute('SELECT id FROM "group" WHERE name=?', (self._block_group_name,)).fetchone()
        if row:
            group_id = int(row[0])
            logger.debug(f"Found existing block group '{self._block_group_name}' with id={group_id}")
            return group_id
        try:
            cur = conn.execute(
                'INSERT INTO "group" (enabled, name, date_added, date_modified, description) VALUES (1,?,?,?,?)',
                (self._block_group_name, now, now, "Domains blocked by Pi-hole AI Guardian")
            )
            group_id = int(cur.lastrowid)
            logger.info(f"Created new block group '{self._block_group_name}' with id={group_id}")
            return group_id
        except Exception as e:
            logger.error(f"Failed to create block group '{self._block_group_name}': {e}")
            return None

    def _assign_domain_to_group(self, conn: sqlite3.Connection, domain_id: Optional[int], group_id: Optional[int]):
        if domain_id is None:
            logger.debug("Skipping group assignment: domain_id is None")
            return
        if group_id is None:
            logger.debug("Skipping group assignment: group_id is None")
            return
        try:
            conn.execute(
                "DELETE FROM domainlist_by_group WHERE domainlist_id=? AND group_id=0",
                (domain_id,)
            )
            conn.execute(
                "INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?,?)",
                (domain_id, group_id)
            )
            logger.debug(f"Assigned domainlist_id={domain_id} to group_id={group_id}")
        except Exception as e:
            logger.error(f"Failed to assign domain {domain_id} to group {group_id}: {e}")

    def _domainlist_id(self, conn: sqlite3.Connection, domain: str) -> Optional[int]:
        row = conn.execute("SELECT id FROM domainlist WHERE domain=? AND type=1", (domain,)).fetchone()
        return int(row[0]) if row else None

    def _table_exists(self, conn: sqlite3.Connection, table: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,)
        ).fetchone()
        return row is not None
