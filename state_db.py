from config import *
try:
    from config_local import *
except ImportError:
    pass

import sqlite3
import threading
from contextlib import suppress
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS classifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                category TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                classified_at TEXT NOT NULL,
                entropy REAL,
                dga_score REAL,
                rule_score INTEGER,
                brand TEXT,
                brand_confidence REAL,
                tld TEXT,
                tld_risk REAL,
                is_punycode INTEGER
            );
            CREATE TABLE IF NOT EXISTS threat_domains (
                domain TEXT PRIMARY KEY,
                feed_name TEXT NOT NULL,
                added_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS popular_domains (
                domain TEXT PRIMARY KEY,
                rank INTEGER NOT NULL
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
        self._migrate_schema()

    def _migrate_schema(self):
        # classifications columns
        cls_columns = {row["name"] for row in self._conn().execute("PRAGMA table_info(classifications)")}
        cls_additions = {
            "entropy": "REAL", "dga_score": "REAL", "rule_score": "INTEGER",
            "brand": "TEXT", "brand_confidence": "REAL", "tld": "TEXT",
            "tld_risk": "REAL", "is_punycode": "INTEGER",
        }
        for name, col_type in cls_additions.items():
            if name not in cls_columns:
                with suppress(sqlite3.OperationalError):
                    self._conn().execute(f"ALTER TABLE classifications ADD COLUMN {name} {col_type}")

        # seen_domains: add last_seen if missing
        seen_columns = {row["name"] for row in self._conn().execute("PRAGMA table_info(seen_domains)")}
        if "last_seen" not in seen_columns:
            with suppress(sqlite3.OperationalError):
                self._conn().execute("ALTER TABLE seen_domains ADD COLUMN last_seen TEXT")
                # backfill last_seen = first_seen for existing rows
                self._conn().execute("UPDATE seen_domains SET last_seen = first_seen WHERE last_seen IS NULL")

        self._conn().commit()

    # ── seen domains ──────────────────────────────────────────────────────────

    def mark_domain_seen(self, domain: str):
        now = _now()
        self._conn().execute(
            """INSERT INTO seen_domains (domain, first_seen, last_seen) VALUES (?,?,?)
               ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen""",
            (domain, now, now)
        )
        self._conn().commit()

    def filter_unseen(self, domains: list[str]) -> list[str]:
        """Return domains not seen within SEEN_DOMAIN_TTL_DAYS (or never seen)."""
        if not domains:
            return []
        placeholders = ",".join("?" * len(domains))
        # Re-classify domains whose last_seen is older than TTL
        cutoff = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat()
        # Simple cutoff: domains seen more than TTL days ago are treated as unseen
        cur = self._conn().execute(
            f"""SELECT domain FROM seen_domains
                WHERE domain IN ({placeholders})
                AND last_seen >= datetime('now', '-{SEEN_DOMAIN_TTL_DAYS} days')""",
            domains
        )
        recently_seen = {row["domain"] for row in cur.fetchall()}
        return [d for d in domains if d not in recently_seen]

    def is_domain_seen(self, domain: str) -> bool:
        """Check if domain was seen within TTL window."""
        cur = self._conn().execute(
            f"""SELECT 1 FROM seen_domains WHERE domain=?
                AND last_seen >= datetime('now', '-{SEEN_DOMAIN_TTL_DAYS} days')""",
            (domain,)
        )
        return cur.fetchone() is not None

    def get_last_verdict(self, domain: str) -> dict | None:
        """Return most recent classification verdict for a domain."""
        cur = self._conn().execute(
            "SELECT category, confidence, blocked FROM classifications WHERE domain=? ORDER BY classified_at DESC LIMIT 1",
            (domain,)
        )
        row = cur.fetchone()
        return dict(row) if row else None

    # ── classifications ───────────────────────────────────────────────────────

    def log_classification(self, domain: str, category: str, confidence: float,
                           reason: str, blocked: bool, features: dict = None):
        feature_values = self._classification_feature_values(features or {})
        self._conn().execute(
            """INSERT INTO classifications
               (domain, category, confidence, reason, blocked, classified_at,
                entropy, dga_score, rule_score, brand, brand_confidence, tld, tld_risk, is_punycode)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (domain, category, confidence, reason, int(blocked),
             _now(), *feature_values)
        )
        self._conn().commit()

    def _classification_feature_values(self, features: dict) -> tuple:
        brand = features.get("brand", {})
        tld = features.get("tld", {})
        punycode = features.get("punycode", {})
        return (
            features.get("entropy", {}).get("shannon"),
            features.get("dga_score"),
            features.get("rules", {}).get("rule_score"),
            brand.get("matched_brand"),
            brand.get("confidence"),
            tld.get("tld"),
            tld.get("tld_risk"),
            int(bool(punycode.get("is_punycode"))) if punycode else None,
        )

    def get_recent_classifications(self, limit: int = 50) -> list[dict]:
        cur = self._conn().execute(
            "SELECT * FROM classifications ORDER BY classified_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ── threat domains ────────────────────────────────────────────────────────

    def is_threat_domain_known(self, domain: str) -> bool:
        cur = self._conn().execute(
            "SELECT 1 FROM threat_domains WHERE domain=?", (domain,)
        )
        return cur.fetchone() is not None

    def mark_threat_domain_known(self, domain: str, feed: str):
        self._conn().execute(
            "INSERT OR IGNORE INTO threat_domains (domain, feed_name, added_at) VALUES (?,?,?)",
            (domain, feed, _now())
        )
        self._conn().commit()

    def bulk_mark_threat_domains(self, domains: list[str], feed: str):
        now = _now()
        self._conn().executemany(
            "INSERT OR IGNORE INTO threat_domains (domain, feed_name, added_at) VALUES (?,?,?)",
            [(d, feed, now) for d in domains]
        )
        self._conn().commit()

    # ── popular domains ───────────────────────────────────────────────────────

    def replace_popular_domains(self, ranks: dict[str, int]):
        """Atomically replace the popularity allowlist with a fresh snapshot."""
        conn = self._conn()
        with conn:
            conn.execute("DELETE FROM popular_domains")
            conn.executemany(
                "INSERT INTO popular_domains (domain, rank) VALUES (?,?)",
                ranks.items()
            )

    def get_popularity_rank(self, domain: str) -> int | None:
        cur = self._conn().execute(
            "SELECT rank FROM popular_domains WHERE domain=?", (domain,)
        )
        row = cur.fetchone()
        return row["rank"] if row else None

    def get_top_domains(self, max_rank: int) -> dict[str, int]:
        cur = self._conn().execute(
            "SELECT domain, rank FROM popular_domains WHERE rank<=?", (max_rank,)
        )
        return {row["domain"]: row["rank"] for row in cur.fetchall()}

    # ── sync log ──────────────────────────────────────────────────────────────

    def log_sync_run(self, feed_name: str, domains_added: int, domains_skipped: int):
        self._conn().execute(
            "INSERT INTO sync_log (feed_name, domains_added, domains_skipped, synced_at) VALUES (?,?,?,?)",
            (feed_name, domains_added, domains_skipped, _now())
        )
        self._conn().commit()

    def hours_since_last_sync(self, feed_name: str) -> float | None:
        """Return hours since last sync for a feed, or None if never synced."""
        cur = self._conn().execute(
            "SELECT synced_at FROM sync_log WHERE feed_name=? ORDER BY synced_at DESC LIMIT 1",
            (feed_name,)
        )
        row = cur.fetchone()
        if not row:
            return None
        last = datetime.fromisoformat(row["synced_at"])
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - last
        return delta.total_seconds() / 3600

    def get_sync_history(self, limit: int = 20) -> list[dict]:
        cur = self._conn().execute(
            "SELECT * FROM sync_log ORDER BY synced_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def close(self):
        if hasattr(self._local, "conn"):
            self._local.conn.close()
