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
