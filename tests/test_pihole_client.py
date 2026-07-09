import os, sys, sqlite3, tempfile, pytest
from unittest.mock import patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pihole_client

FIXTURE_LOG = os.path.join(os.path.dirname(__file__), "fixtures", "sample_ftl.log")

def test_extract_domains_from_log_lines():
    with open(FIXTURE_LOG) as f:
        lines = f.readlines()
    domains = pihole_client.extract_domains_from_lines(lines)
    assert "google.com" in domains
    assert "evil-malware.ru" in domains
    assert "tracker.example.com" in domains
    assert "suspiciousdomain.xyz" in domains

def test_skip_ptr_queries():
    with open(FIXTURE_LOG) as f:
        lines = f.readlines()
    domains = pihole_client.extract_domains_from_lines(lines)
    assert not any(".in-addr.arpa" in d for d in domains)

def test_skip_pihole_internal():
    with open(FIXTURE_LOG) as f:
        lines = f.readlines()
    domains = pihole_client.extract_domains_from_lines(lines)
    assert "pi.hole" not in domains

def test_skip_resolver_arpa():
    with open(FIXTURE_LOG) as f:
        lines = f.readlines()
    domains = pihole_client.extract_domains_from_lines(lines)
    assert "_dns.resolver.arpa" not in domains

def test_add_to_denylist(tmp_path):
    db_path = str(tmp_path / "gravity.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE domainlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        type INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        date_added INTEGER NOT NULL,
        date_modified INTEGER NOT NULL,
        comment TEXT
    )""")
    conn.commit()
    conn.close()

    client = pihole_client.PiholeClient(db_path=db_path, reload_cmd=None)
    added = client.add_to_denylist(["evil.com", "bad.ru"], comment="AI:MALWARE:0.95")
    assert added == 2

    conn = sqlite3.connect(db_path)
    cur = conn.execute("SELECT domain FROM domainlist WHERE type=1")
    domains = [r[0] for r in cur.fetchall()]
    conn.close()
    assert "evil.com" in domains
    assert "bad.ru" in domains

def test_add_duplicate_skipped(tmp_path):
    db_path = str(tmp_path / "gravity.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE domainlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        type INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        date_added INTEGER NOT NULL,
        date_modified INTEGER NOT NULL,
        comment TEXT
    )""")
    conn.commit()
    conn.close()

    client = pihole_client.PiholeClient(db_path=db_path, reload_cmd=None)
    client.add_to_denylist(["evil.com"], comment="first")
    added = client.add_to_denylist(["evil.com"], comment="duplicate")
    assert added == 0

def test_add_to_denylist_skips_never_block_domains(tmp_path):
    db_path = str(tmp_path / "gravity.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE domainlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        type INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        date_added INTEGER NOT NULL,
        date_modified INTEGER NOT NULL,
        comment TEXT
    )""")
    conn.commit()
    conn.close()

    client = pihole_client.PiholeClient(db_path=db_path, reload_cmd=None)
    added = client.add_to_denylist(
        ["instagram.c10r.instagram.com", "graph.facebook.com", "evil.com"],
        comment="AI:MALWARE:0.99",
    )

    conn = sqlite3.connect(db_path)
    cur = conn.execute("SELECT domain FROM domainlist")
    domains = [r[0] for r in cur.fetchall()]
    conn.close()

    assert added == 1
    assert domains == ["evil.com"]

def test_add_to_denylist_can_reload_immediately_when_interval_disabled(tmp_path):
    db_path = str(tmp_path / "gravity.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE domainlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        type INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        date_added INTEGER NOT NULL,
        date_modified INTEGER NOT NULL,
        comment TEXT
    )""")
    conn.commit()
    conn.close()

    with patch("pihole_client.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stderr = ""
        client = pihole_client.PiholeClient(
            db_path=db_path,
            reload_cmd="sudo -n /usr/local/bin/pihole reloadlists",
            reload_interval_seconds=0,
        )
        added = client.add_to_denylist(["evil.com"], comment="AI:MALWARE:0.95")

    assert added == 1
    run.assert_called_once_with(
        ["sudo", "-n", "/usr/local/bin/pihole", "reloadlists"],
        capture_output=True,
        text=True,
        timeout=15,
    )

def test_add_to_denylist_batches_reload_until_interval_or_flush(tmp_path):
    db_path = str(tmp_path / "gravity.db")
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE domainlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        type INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        date_added INTEGER NOT NULL,
        date_modified INTEGER NOT NULL,
        comment TEXT
    )""")
    conn.commit()
    conn.close()

    timers = []

    class FakeTimer:
        def __init__(self, interval, callback):
            self.interval = interval
            self.callback = callback
            self.daemon = False
            self.started = False

        def start(self):
            self.started = True
            timers.append(self)

        def is_alive(self):
            return self.started

        def cancel(self):
            self.started = False

    with patch("pihole_client.threading.Timer", FakeTimer), \
         patch("pihole_client.subprocess.run") as run:
        run.return_value.returncode = 0
        run.return_value.stderr = ""
        client = pihole_client.PiholeClient(
            db_path=db_path,
            reload_cmd="sudo -n /usr/local/bin/pihole reloadlists",
            reload_interval_seconds=60,
        )
        assert client.add_to_denylist(["evil.com"], comment="AI:MALWARE:0.95") == 1
        assert client.add_to_denylist(["bad.ru"], comment="AI:MALWARE:0.95") == 1
        run.assert_not_called()
        assert len(timers) == 1
        assert timers[0].interval == 60

        client.flush_reload()

    run.assert_called_once_with(
        ["sudo", "-n", "/usr/local/bin/pihole", "reloadlists"],
        capture_output=True,
        text=True,
        timeout=15,
    )
