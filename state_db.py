from config import *
try:
    from config_local import *
except ImportError:
    pass

import json
import logging
import sqlite3
import threading
from contextlib import suppress
from datetime import datetime, timedelta, timezone

# Stay well under SQLITE_MAX_VARIABLE_NUMBER (999 on older builds) — feed
# domain lists run to 40k+ entries.
_SQL_CHUNK = 500


def _chunks(items: list, size: int = _SQL_CHUNK):
    for i in range(0, len(items), size):
        yield items[i:i + size]


logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cutoff(days: float) -> str:
    """ISO cutoff timestamp `days` ago — same format _now() stores, so string
    comparison is exact (sqlite datetime() formats differ)."""
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


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
                added_at TEXT NOT NULL,
                last_seen TEXT
            );
            CREATE TABLE IF NOT EXISTS popular_domains (
                domain TEXT PRIMARY KEY,
                rank INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shared_hosting_suffixes (
                suffix TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS domain_registration (
                domain TEXT PRIMARY KEY,
                created_at TEXT,
                fetched_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bad_asns (
                asn INTEGER PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS domain_asn (
                domain TEXT PRIMARY KEY,
                asn INTEGER,
                fetched_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS domain_tls (
                domain TEXT PRIMARY KEY,
                info TEXT,
                fetched_at TEXT NOT NULL
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

        # threat_domains: add last_seen if missing
        threat_columns = {row["name"] for row in self._conn().execute("PRAGMA table_info(threat_domains)")}
        if "last_seen" not in threat_columns:
            with suppress(sqlite3.OperationalError):
                self._conn().execute("ALTER TABLE threat_domains ADD COLUMN last_seen TEXT")
        with suppress(sqlite3.OperationalError):
            self._conn().execute("UPDATE threat_domains SET last_seen = added_at WHERE last_seen IS NULL")

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
        cutoff = _cutoff(SEEN_DOMAIN_TTL_DAYS)
        recently_seen = set()
        for chunk in _chunks(domains):
            placeholders = ",".join("?" * len(chunk))
            cur = self._conn().execute(
                f"""SELECT domain FROM seen_domains
                    WHERE domain IN ({placeholders}) AND last_seen >= ?""",
                [*chunk, cutoff]
            )
            recently_seen.update(row["domain"] for row in cur.fetchall())
        return [d for d in domains if d not in recently_seen]

    def prune_old_data(self, days: float = DB_RETENTION_DAYS):
        """Delete history older than `days` — the DB must not grow forever on a Pi."""
        cutoff = _cutoff(days)
        conn = self._conn()
        with conn:
            for table, column in (
                ("classifications", "classified_at"),
                ("sync_log", "synced_at"),
                ("seen_domains", "last_seen"),
                ("domain_asn", "fetched_at"),
                ("domain_tls", "fetched_at"),
            ):
                cur = conn.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
                if cur.rowcount:
                    logger.info(f"Pruned {cur.rowcount} rows from {table} (older than {days}d)")

    def is_domain_seen(self, domain: str) -> bool:
        """Check if domain was seen within TTL window."""
        cur = self._conn().execute(
            "SELECT 1 FROM seen_domains WHERE domain=? AND last_seen >= ?",
            (domain, _cutoff(SEEN_DOMAIN_TTL_DAYS))
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
        now = _now()
        self._conn().execute(
            """INSERT INTO threat_domains (domain, feed_name, added_at, last_seen) VALUES (?,?,?,?)
               ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen""",
            (domain, feed, now, now)
        )
        self._conn().commit()

    def bulk_mark_threat_domains(self, domains: list[str], feed: str):
        now = _now()
        self._conn().executemany(
            """INSERT INTO threat_domains (domain, feed_name, added_at, last_seen) VALUES (?,?,?,?)
               ON CONFLICT(domain) DO UPDATE SET last_seen=excluded.last_seen""",
            [(d, feed, now, now) for d in domains]
        )
        self._conn().commit()

    def touch_threat_domains(self, domains: list[str]):
        """Refresh last_seen for domains re-observed in a feed; unknown domains ignored."""
        if not domains:
            return
        now = _now()
        for chunk in _chunks(domains):
            placeholders = ",".join("?" * len(chunk))
            self._conn().execute(
                f"UPDATE threat_domains SET last_seen=? WHERE domain IN ({placeholders})",
                [now, *chunk]
            )
        self._conn().commit()

    def get_expired_threat_domains(self, days: float) -> list[str]:
        """Domains not re-seen in any feed within the last `days` days."""
        cur = self._conn().execute(
            "SELECT domain FROM threat_domains WHERE last_seen < ?",
            (_cutoff(days),)
        )
        return [row["domain"] for row in cur.fetchall()]

    def delete_threat_domains(self, domains: list[str]):
        if not domains:
            return
        for chunk in _chunks(domains):
            placeholders = ",".join("?" * len(chunk))
            self._conn().execute(
                f"DELETE FROM threat_domains WHERE domain IN ({placeholders})", chunk
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

    # ── shared hosting suffixes (PSL private section) ────────────────────────

    def replace_shared_hosting_suffixes(self, suffixes: set[str]):
        """Atomically replace the shared-hosting suffix snapshot."""
        conn = self._conn()
        with conn:
            conn.execute("DELETE FROM shared_hosting_suffixes")
            conn.executemany(
                "INSERT INTO shared_hosting_suffixes (suffix) VALUES (?)",
                [(s,) for s in suffixes]
            )

    def get_shared_hosting_suffixes(self) -> set[str]:
        cur = self._conn().execute("SELECT suffix FROM shared_hosting_suffixes")
        return {row["suffix"] for row in cur.fetchall()}

    # ── domain registration (RDAP cache) ─────────────────────────────────────

    def get_domain_registration(self, domain: str) -> dict | None:
        cur = self._conn().execute(
            "SELECT created_at, fetched_at FROM domain_registration WHERE domain=?",
            (domain,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {"created_at": row["created_at"], "fetched_at": row["fetched_at"]}

    def cache_domain_registration(self, domain: str, created_at: str | None):
        conn = self._conn()
        with conn:
            conn.execute(
                """INSERT INTO domain_registration (domain, created_at, fetched_at)
                   VALUES (?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET
                     created_at=excluded.created_at, fetched_at=excluded.fetched_at""",
                (domain, created_at, _now())
            )

    # ── ASN reputation ────────────────────────────────────────────────────────

    def replace_bad_asns(self, asns: set[int]):
        """Atomically replace the DROP-listed ASN snapshot."""
        conn = self._conn()
        with conn:
            conn.execute("DELETE FROM bad_asns")
            conn.executemany(
                "INSERT INTO bad_asns (asn) VALUES (?)",
                [(a,) for a in asns]
            )

    def is_bad_asn(self, asn: int) -> bool:
        cur = self._conn().execute("SELECT 1 FROM bad_asns WHERE asn=?", (asn,))
        return cur.fetchone() is not None

    def get_domain_asn(self, domain: str) -> dict | None:
        cur = self._conn().execute(
            "SELECT asn, fetched_at FROM domain_asn WHERE domain=?", (domain,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {"asn": row["asn"], "fetched_at": row["fetched_at"]}

    def cache_domain_asn(self, domain: str, asn: int | None):
        conn = self._conn()
        with conn:
            conn.execute(
                """INSERT INTO domain_asn (domain, asn, fetched_at)
                   VALUES (?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET
                     asn=excluded.asn, fetched_at=excluded.fetched_at""",
                (domain, asn, _now())
            )

    # ── TLS cert cache ────────────────────────────────────────────────────────

    def get_domain_tls(self, domain: str) -> dict | None:
        cur = self._conn().execute(
            "SELECT info, fetched_at FROM domain_tls WHERE domain=?", (domain,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        info = json.loads(row["info"]) if row["info"] is not None else None
        return {"info": info, "fetched_at": row["fetched_at"]}

    def cache_domain_tls(self, domain: str, info: dict | None):
        conn = self._conn()
        with conn:
            conn.execute(
                """INSERT INTO domain_tls (domain, info, fetched_at)
                   VALUES (?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET
                     info=excluded.info, fetched_at=excluded.fetched_at""",
                (domain, json.dumps(info) if info is not None else None, _now())
            )

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
