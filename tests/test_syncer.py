import os, sys
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from syncer import ThreatIntelSyncer


def _make_syncer(state=None, pihole=None, feeds=None, classifier=None):
    state = state or MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = False
    pihole = pihole or MagicMock()
    pihole.add_to_denylist.return_value = 1
    return ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        classifier=classifier,
        feeds=feeds or [{"name": "URLhaus", "url": "http://feed", "category": "MALWARE"}],
    )


def test_syncer_urlhaus_domains_always_pass_rule_verification():
    """URLhaus hit sets rule_score=100, so all URLhaus domains pass verification."""
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = False
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_feed", return_value=["evil.com", "malware.xyz"]):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 1
    pihole.add_to_denylist.assert_called_once_with(
        ["evil.com", "malware.xyz"], comment="TI:MALWARE:URLhaus"
    )
    state.bulk_mark_threat_domains.assert_called_once_with(
        ["evil.com", "malware.xyz"], feed="URLhaus"
    )
    assert state.log_classification.call_count == 2


def test_syncer_skips_already_known_domains():
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = True
    pihole = MagicMock()
    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        feeds=[{"name": "URLhaus", "url": "http://feed", "category": "MALWARE"}],
    )

    with patch("syncer.fetch_feed", return_value=["already.com"]):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 0
    pihole.add_to_denylist.assert_not_called()
    state.bulk_mark_threat_domains.assert_not_called()


def test_syncer_does_not_block_when_classifier_is_unavailable():
    """Classifier=None is now irrelevant — syncer uses rule engine, not classifier."""
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = False
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        classifier=None,
        feeds=[{"name": "URLhaus", "url": "http://feed", "category": "MALWARE"}],
    )

    with patch("syncer.fetch_feed", return_value=["evil.com"]):
        added = syncer._sync_one_feed(syncer._feeds[0])

    # URLhaus domains pass rule verification regardless of classifier
    assert added == 1
    pihole.add_to_denylist.assert_called_once()


def test_syncer_non_urlhaus_low_score_domain_skipped():
    """Non-URLhaus feed domain with low rule_score is rule-skipped."""
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = False
    pihole = MagicMock()
    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        feeds=[{"name": "OpenPhish", "url": "http://feed", "category": "PHISHING"}],
    )

    # "google.com" has low rule_score and is not a URLhaus feed
    with patch("syncer.fetch_feed", return_value=["google.com"]):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 0
    pihole.add_to_denylist.assert_not_called()


def test_syncer_passes_threat_context_to_extractor():
    """Verify threat_context with urlhaus_hit is forwarded to feature extractor."""
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = False
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = _make_syncer(state=state, pihole=pihole)

    captured = {}
    real_extract = __import__("features.extractor", fromlist=["extract"]).extract

    def capturing_extract(domain, threat_context=None, brands=None):
        captured[domain] = threat_context
        return real_extract(domain, threat_context=threat_context, brands=brands)

    with patch("syncer.extract", side_effect=capturing_extract):
        with patch("syncer.fetch_feed", return_value=["evil.com"]):
            syncer._sync_one_feed(syncer._feeds[0])

    assert captured["evil.com"]["urlhaus_hit"] is True
    assert captured["evil.com"]["feed_source"] == "URLhaus"


def test_syncer_syncs_popularity_list_when_never_synced():
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.hours_since_last_sync.return_value = None
    syncer = _make_syncer(state=state)

    with patch("syncer.fetch_popularity_list", return_value={"google.com": 1}) as fetch:
        syncer._sync_popularity()

    fetch.assert_called_once()
    state.replace_popular_domains.assert_called_once_with({"google.com": 1})
    state.log_sync_run.assert_called_once()
    assert state.log_sync_run.call_args.kwargs["feed_name"] == "Tranco"


def test_syncer_skips_popularity_sync_when_fresh():
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.hours_since_last_sync.return_value = 5.0
    syncer = _make_syncer(state=state)

    with patch("syncer.fetch_popularity_list") as fetch:
        syncer._sync_popularity()

    fetch.assert_not_called()
    state.replace_popular_domains.assert_not_called()


def test_syncer_empty_popularity_fetch_does_not_wipe_existing_list():
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.hours_since_last_sync.return_value = None
    syncer = _make_syncer(state=state)

    with patch("syncer.fetch_popularity_list", return_value={}):
        syncer._sync_popularity()

    state.replace_popular_domains.assert_not_called()


def test_syncer_feed_error_does_not_crash_sync_cycle():
    """One feed error is caught and logged; other feeds still run."""
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = False
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        feeds=[
            {"name": "BadFeed", "url": "http://bad", "category": "MALWARE"},
            {"name": "URLhaus", "url": "http://good", "category": "MALWARE"},
        ],
    )

    def side_effect(feed_cfg):
        if feed_cfg["name"] == "BadFeed":
            raise RuntimeError("network error")
        return ["evil.com"]

    with patch("syncer.fetch_feed", side_effect=side_effect):
        syncer._sync_all_feeds()

    pihole.add_to_denylist.assert_called_once()


def test_syncer_never_blocks_popular_apex_from_feed():
    """Feeds list URLs on compromised legit sites — a popular apex must not be
    auto-blocked even on a URLhaus hit."""
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    state.get_popularity_rank.side_effect = lambda apex: 12 if apex == "google.com" else None
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_feed", return_value=["evil.com", "storage.google.com"]):
        syncer._sync_one_feed(syncer._feeds[0])

    pihole.add_to_denylist.assert_called_once_with(["evil.com"], comment="TI:MALWARE:URLhaus")
    state.bulk_mark_threat_domains.assert_called_once_with(["evil.com"], feed="URLhaus")
    # the popular domain is still logged, but not blocked
    logged = {c.kwargs["domain"]: c.kwargs["blocked"] for c in state.log_classification.call_args_list}
    assert logged["storage.google.com"] is False
    assert logged["evil.com"] is True
