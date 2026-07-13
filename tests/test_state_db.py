import os, sys, tempfile, pytest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import state_db

@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "test_state.db")
    db = state_db.StateDB(path)
    yield db
    db.close()

def test_domain_not_seen_initially(db):
    assert db.is_domain_seen("evil.com") is False

def test_mark_domain_seen(db):
    db.mark_domain_seen("evil.com")
    assert db.is_domain_seen("evil.com") is True

def test_log_classification(db):
    db.log_classification("evil.com", "MALWARE", 0.95, "Looks like C2 beacon", blocked=True)
    rows = db.get_recent_classifications(limit=10)
    assert len(rows) == 1
    assert rows[0]["domain"] == "evil.com"
    assert rows[0]["category"] == "MALWARE"
    assert rows[0]["blocked"] == 1

def test_threat_domain_not_seen_initially(db):
    assert db.is_threat_domain_known("badactor.ru") is False

def test_mark_threat_domain_known(db):
    db.mark_threat_domain_known("badactor.ru", feed="Feodo C2 Tracker")
    assert db.is_threat_domain_known("badactor.ru") is True

def test_log_sync_run(db):
    db.log_sync_run(feed_name="URLhaus", domains_added=42, domains_skipped=100)
    rows = db.get_sync_history(limit=5)
    assert rows[0]["feed_name"] == "URLhaus"
    assert rows[0]["domains_added"] == 42

def test_popularity_rank_unknown_initially(db):
    assert db.get_popularity_rank("google.com") is None

def test_replace_popular_domains_stores_ranks(db):
    db.replace_popular_domains({"google.com": 1, "googleapis.com": 30})
    assert db.get_popularity_rank("googleapis.com") == 30
    assert db.get_popularity_rank("google.com") == 1

def test_replace_popular_domains_clears_previous_list(db):
    db.replace_popular_domains({"old.com": 5})
    db.replace_popular_domains({"new.com": 7})
    assert db.get_popularity_rank("old.com") is None
    assert db.get_popularity_rank("new.com") == 7

def test_get_top_domains_returns_ranked_subset(db):
    db.replace_popular_domains({"google.com": 1, "paypal.com": 800, "deep.com": 50000})
    top = db.get_top_domains(1000)
    assert top == {"google.com": 1, "paypal.com": 800}

def test_get_top_domains_empty_when_no_list(db):
    assert db.get_top_domains(1000) == {}

def test_batch_check_seen(db):
    db.mark_domain_seen("a.com")
    db.mark_domain_seen("b.com")
    result = db.filter_unseen(["a.com", "b.com", "c.com"])
    assert result == ["c.com"]


def test_domain_registration_cache_roundtrip(db):
    assert db.get_domain_registration("evil.com") is None
    db.cache_domain_registration("evil.com", "2020-01-15T09:30:00+00:00")
    cached = db.get_domain_registration("evil.com")
    assert cached["created_at"] == "2020-01-15T09:30:00+00:00"
    assert cached["fetched_at"]

def test_domain_registration_negative_cache_stores_null(db):
    db.cache_domain_registration("unknown.tld", None)
    cached = db.get_domain_registration("unknown.tld")
    assert cached["created_at"] is None
    assert cached["fetched_at"]

def test_domain_registration_cache_upsert(db):
    db.cache_domain_registration("evil.com", None)
    db.cache_domain_registration("evil.com", "2024-01-01T00:00:00+00:00")
    assert db.get_domain_registration("evil.com")["created_at"] == "2024-01-01T00:00:00+00:00"


# ── TI block expiry ───────────────────────────────────────────────────────────

def test_touch_threat_domains_refreshes_last_seen(db):
    db.mark_threat_domain_known("old.ru", feed="URLhaus")
    db._conn().execute("UPDATE threat_domains SET last_seen='2020-01-01T00:00:00+00:00'")
    db._conn().commit()
    db.touch_threat_domains(["old.ru", "not-tracked.com"])
    assert db.get_expired_threat_domains(days=30) == []

def test_get_expired_threat_domains_returns_stale_only(db):
    db.mark_threat_domain_known("stale.ru", feed="URLhaus")
    db.mark_threat_domain_known("fresh.ru", feed="URLhaus")
    db._conn().execute(
        "UPDATE threat_domains SET last_seen='2020-01-01T00:00:00+00:00' WHERE domain='stale.ru'"
    )
    db._conn().commit()
    assert db.get_expired_threat_domains(days=30) == ["stale.ru"]

def test_delete_threat_domains_removes_rows(db):
    db.mark_threat_domain_known("gone.ru", feed="URLhaus")
    db.delete_threat_domains(["gone.ru"])
    assert db.is_threat_domain_known("gone.ru") is False

def test_threat_domains_last_seen_migration_backfills_from_added_at(tmp_path):
    import sqlite3
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE threat_domains (
            domain TEXT PRIMARY KEY,
            feed_name TEXT NOT NULL,
            added_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        "INSERT INTO threat_domains VALUES ('legacy.ru','URLhaus','2020-01-01T00:00:00+00:00')"
    )
    conn.commit()
    conn.close()
    legacy = state_db.StateDB(path)
    assert legacy.get_expired_threat_domains(days=30) == ["legacy.ru"]
    legacy.close()


# ── shared hosting suffixes ───────────────────────────────────────────────────

def test_shared_hosting_suffixes_empty_initially(db):
    assert db.get_shared_hosting_suffixes() == set()

def test_replace_shared_hosting_suffixes_roundtrip(db):
    db.replace_shared_hosting_suffixes({"github.io", "pages.dev"})
    assert db.get_shared_hosting_suffixes() == {"github.io", "pages.dev"}

def test_replace_shared_hosting_suffixes_clears_previous(db):
    db.replace_shared_hosting_suffixes({"old.example"})
    db.replace_shared_hosting_suffixes({"new.example"})
    assert db.get_shared_hosting_suffixes() == {"new.example"}


# ── ASN reputation ────────────────────────────────────────────────────────────

def test_bad_asn_unknown_initially(db):
    assert db.is_bad_asn(205112) is False

def test_replace_bad_asns_roundtrip(db):
    db.replace_bad_asns({205112, 401199})
    assert db.is_bad_asn(205112) is True
    assert db.is_bad_asn(13335) is False

def test_replace_bad_asns_clears_previous(db):
    db.replace_bad_asns({111})
    db.replace_bad_asns({222})
    assert db.is_bad_asn(111) is False
    assert db.is_bad_asn(222) is True

def test_domain_asn_cache_roundtrip(db):
    assert db.get_domain_asn("evil.com") is None
    db.cache_domain_asn("evil.com", 205112)
    cached = db.get_domain_asn("evil.com")
    assert cached["asn"] == 205112
    assert cached["fetched_at"]

def test_domain_asn_negative_cache_stores_null(db):
    db.cache_domain_asn("dead.example", None)
    cached = db.get_domain_asn("dead.example")
    assert cached["asn"] is None
    assert cached["fetched_at"]

def test_domain_asn_cache_upsert(db):
    db.cache_domain_asn("evil.com", None)
    db.cache_domain_asn("evil.com", 401199)
    assert db.get_domain_asn("evil.com")["asn"] == 401199


# ── TLS cert cache ────────────────────────────────────────────────────────────

def test_domain_tls_cache_roundtrip(db):
    assert db.get_domain_tls("evil.example") is None
    info = {"issuer": "Let's Encrypt", "san_count": 2, "verify_failed": False,
            "fail_reason": None, "not_before": "2026-06-01T00:00:00+00:00"}
    db.cache_domain_tls("evil.example", info)
    cached = db.get_domain_tls("evil.example")
    assert cached["info"] == info
    assert cached["fetched_at"]

def test_domain_tls_negative_cache_stores_null(db):
    db.cache_domain_tls("dead.example", None)
    cached = db.get_domain_tls("dead.example")
    assert cached["info"] is None
    assert cached["fetched_at"]

def test_domain_tls_cache_upsert(db):
    db.cache_domain_tls("evil.example", None)
    db.cache_domain_tls("evil.example", {"issuer": "X", "san_count": 1,
                                         "verify_failed": True, "fail_reason": "expired",
                                         "not_before": None})
    assert db.get_domain_tls("evil.example")["info"]["issuer"] == "X"
