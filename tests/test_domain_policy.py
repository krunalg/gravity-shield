import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import domain_policy


def _use_allowlist(monkeypatch, tmp_path, content: str):
    path = str(tmp_path / "allowlist.txt")
    with open(path, "w") as f:
        f.write(content)
    monkeypatch.setattr(domain_policy, "USER_ALLOWLIST_PATH", path)
    return path


def test_user_allowlist_exact_domain_is_never_blocked(monkeypatch, tmp_path):
    _use_allowlist(monkeypatch, tmp_path, "myserver.example.com\n")
    assert domain_policy.is_never_block_domain("myserver.example.com") is True
    assert domain_policy.is_never_block_domain("evil.com") is False


def test_user_allowlist_suffix_line_covers_subdomains(monkeypatch, tmp_path):
    _use_allowlist(monkeypatch, tmp_path, ".corp.example.com\n")
    assert domain_policy.is_never_block_domain("vpn.corp.example.com") is True
    assert domain_policy.is_never_block_domain("corp-example.com") is False


def test_user_allowlist_ignores_comments_and_blank_lines(monkeypatch, tmp_path):
    _use_allowlist(monkeypatch, tmp_path, "# comment\n\nGOOD.example.com \n")
    assert domain_policy.is_never_block_domain("good.example.com") is True


def test_missing_allowlist_file_is_fine(monkeypatch, tmp_path):
    monkeypatch.setattr(domain_policy, "USER_ALLOWLIST_PATH",
                        str(tmp_path / "does-not-exist.txt"))
    assert domain_policy.is_never_block_domain("evil.com") is False
    assert domain_policy.is_never_block_domain("pi.hole") is True  # config still applies


def test_allowlist_edits_picked_up_without_restart(monkeypatch, tmp_path):
    path = _use_allowlist(monkeypatch, tmp_path, "first.example.com\n")
    assert domain_policy.is_never_block_domain("second.example.com") is False
    with open(path, "w") as f:
        f.write("second.example.com\n")
    os.utime(path, (0, os.stat(path).st_mtime + 5))
    assert domain_policy.is_never_block_domain("second.example.com") is True


def test_daemon_infra_hostnames_are_skipped():
    """The daemon's own feed/RDAP endpoints must not be classified."""
    assert domain_policy.should_skip_classification("urlhaus.abuse.ch") is True
    assert domain_policy.should_skip_classification("openphish.com") is True
    assert domain_policy.should_skip_classification("data.iana.org") is True
    assert domain_policy.should_skip_classification("publicsuffix.org") is True
    assert domain_policy.should_skip_classification("www.spamhaus.org") is True
    assert domain_policy.should_skip_classification("tranco-list.eu") is True
    # unrelated domains unaffected
    assert domain_policy.should_skip_classification("evil.com") is False
