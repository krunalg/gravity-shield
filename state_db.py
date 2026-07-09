try:
    from config_local import *
except ImportError:
    pass
from config import *

import sqlite3
import threading
from datetime import datetime


class StateDB:
    def __init__(self, db_path: str):
        self._path = db_path
        self._local = threading.local()
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self._path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_schema(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS seen_domains (
                domain TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS classifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                classified_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS threat_domains (
                domain TEXT PRIMARY KEY,
                feed_name TEXT NOT NULL,
                added_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_name TEXT NOT NULL,
                domains_added INTEGER NOT NULL,
                domains_skipped INTEGER NOT NULL,
                synced_at TEXT NOT NULL
            );
        """)
        conn.commit()

    def is_domain_seen(self, domain: str) -> bool:
        cur = self._conn().execute(
            "SELECT 1 FROM seen_domains WHERE domain=?", (domain,)
        )
        return cur.fetchone() is not None

    def mark_domain_seen(self, domain: str):
        self._conn().execute(
            "INSERT OR IGNORE INTO seen_domains (domain, first_seen) VALUES (?,?)",
            (domain, datetime.utcnow().isoformat())
        )
        self._conn().commit()

    def filter_unseen(self, domains: list[str]) -> list[str]:
        if not domains:
            return []
        placeholders = ",".join("?" * len(domains))
        cur = self._conn().execute(
            f"SELECT domain FROM seen_domains WHERE domain IN ({placeholders})",
            domains
        )
        seen = {row["domain"] for row in cur.fetchall()}
        return [d for d in domains if d not in seen]

    def log_classification(self, domain: str, category: str, confidence: float,
                           reason: str, blocked: bool):
        self._conn().execute(
            """INSERT INTO classifications
               (domain, category, confidence, reason, blocked, classified_at)
               VALUES (?,?,?,?,?,?)""",
            (domain, category, confidence, reason, int(blocked),
             datetime.utcnow().isoformat())
        )
        self._conn().commit()

    def get_recent_classifications(self, limit: int = 50) -> list[dict]:
        cur = self._conn().execute(
            "SELECT * FROM classifications ORDER BY classified_at DESC LIMIT ?",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def is_threat_domain_known(self, domain: str) -> bool:
        cur = self._conn().execute(
            "SELECT 1 FROM threat_domains WHERE domain=?", (domain,)
        )
        return cur.fetchone() is not None

    def mark_threat_domain_known(self, domain: str, feed: str):
        self._conn().execute(
            "INSERT OR IGNORE INTO threat_domains (domain, feed_name, added_at) VALUES (?,?,?)",
            (domain, feed, datetime.utcnow().isoformat())
        )
        self._conn().commit()

    def bulk_mark_threat_domains(self, domains: list[str], feed: str):
        now = datetime.utcnow().isoformat()
        self._conn().executemany(
            "INSERT OR IGNORE INTO threat_domains (domain, feed_name, added_at) VALUES (?,?,?)",
            [(d, feed, now) for d in domains]
        )
        self._conn().commit()

    def log_sync_run(self, feed_name: str, domains_added: int, domains_skipped: int):
        self._conn().execute(
            """INSERT INTO sync_log (feed_name, domains_added, domains_skipped, synced_at)
               VALUES (?,?,?,?)""",
            (feed_name, domains_added, domains_skipped, datetime.utcnow().isoformat())
        )
        self._conn().commit()

    def get_sync_history(self, limit: int = 20) -> list[dict]:
        cur = self._conn().execute(
            "SELECT * FROM sync_log ORDER BY synced_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def close(self):
        if hasattr(self._local, "conn"):
            self._local.conn.close()
