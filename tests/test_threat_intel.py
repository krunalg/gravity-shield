import os, sys
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import threat_intel
import config

FIXTURE_FEED = os.path.join(os.path.dirname(__file__), "fixtures", "sample_feed.txt")

def _mock_get(text: str):
    mock = MagicMock()
    mock.text = text
    mock.raise_for_status = MagicMock()
    return mock

def test_parse_hosts_format():
    with open(FIXTURE_FEED) as f:
        content = f.read()
    domains = threat_intel.parse_feed_content(content, comment_prefix="#", is_url_list=False)
    assert "evilc2server.ru" in domains
    assert "botnet-panel.xyz" in domains
    assert "malware-drop.cc" in domains
    assert "legitimate.com" in domains

def test_parse_skips_comments():
    content = "# this is a comment\nevil.com\n# another comment\nbad.ru"
    domains = threat_intel.parse_feed_content(content, comment_prefix="#", is_url_list=False)
    assert "evil.com" in domains
    assert "bad.ru" in domains
    assert len([d for d in domains if d.startswith("#")]) == 0

def test_parse_url_list_extracts_domain():
    content = "http://phishing.example.com/fake-login\nhttps://steal.xyz/bank"
    domains = threat_intel.parse_feed_content(content, comment_prefix="#", is_url_list=True)
    assert "phishing.example.com" in domains
    assert "steal.xyz" in domains

def test_parse_skips_ip_addresses():
    content = "192.168.1.1\nevil.com\n10.0.0.1"
    domains = threat_intel.parse_feed_content(content, comment_prefix="#", is_url_list=False)
    assert "evil.com" in domains
    assert "192.168.1.1" not in domains
    assert "10.0.0.1" not in domains

def test_parse_strips_hosts_prefix():
    content = "0.0.0.0 malware.ru\n127.0.0.1 bad.com"
    domains = threat_intel.parse_feed_content(content, comment_prefix="#", is_url_list=False)
    assert "malware.ru" in domains
    assert "bad.com" in domains
    assert "0.0.0.0" not in domains

def test_fetch_feed_returns_domains():
    with patch("threat_intel.requests.get") as mock_get:
        mock_get.return_value = _mock_get("evil.com\nbad.ru")
        feed_cfg = {"url": "http://fake", "comment_prefix": "#", "is_url_list": False, "name": "test"}
        domains = threat_intel.fetch_feed(feed_cfg)
        assert "evil.com" in domains
        assert "bad.ru" in domains

def test_fetch_feed_returns_empty_on_error():
    with patch("threat_intel.requests.get", side_effect=Exception("network error")):
        feed_cfg = {"url": "http://fake", "comment_prefix": "#", "is_url_list": False, "name": "test"}
        domains = threat_intel.fetch_feed(feed_cfg)
        assert domains == []

def test_default_feeds_do_not_include_retired_feodo_domain_feed():
    feed_urls = [feed["url"] for feed in config.THREAT_INTEL_FEEDS]
    feed_names = [feed["name"] for feed in config.THREAT_INTEL_FEEDS]

    assert "https://feodotracker.abuse.ch/downloads/domainblocklist.txt" not in feed_urls
    assert "Feodo C2 Tracker" not in feed_names
