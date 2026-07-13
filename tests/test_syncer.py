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
    # ALL processed domains marked known — skipped ones must not be re-verified
    # (and re-logged) every 6h cycle
    state.bulk_mark_threat_domains.assert_called_once_with(
        ["evil.com", "storage.google.com"], feed="URLhaus"
    )
    # the popular domain is still logged, but not blocked
    logged = {c.kwargs["domain"]: c.kwargs["blocked"] for c in state.log_classification.call_args_list}
    assert logged["storage.google.com"] is False
    assert logged["evil.com"] is True


def test_syncer_expires_stale_ti_blocks():
    """Domains not re-seen in feeds for TI_BLOCK_EXPIRY_DAYS are unblocked."""
    state = MagicMock()
    state.get_expired_threat_domains.return_value = ["stale.ru"]
    pihole = MagicMock()
    pihole.remove_from_denylist.return_value = 1
    syncer = _make_syncer(state=state, pihole=pihole)

    syncer._expire_stale_blocks()

    state.get_expired_threat_domains.assert_called_once()
    pihole.remove_from_denylist.assert_called_once_with(["stale.ru"], comment_prefix="TI:")
    state.delete_threat_domains.assert_called_once_with(["stale.ru"])


def test_syncer_expiry_disabled_when_days_zero():
    state = MagicMock()
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.TI_BLOCK_EXPIRY_DAYS", 0):
        syncer._expire_stale_blocks()

    state.get_expired_threat_domains.assert_not_called()
    pihole.remove_from_denylist.assert_not_called()


def test_syncer_expiry_no_stale_domains_noop():
    state = MagicMock()
    state.get_expired_threat_domains.return_value = []
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    syncer._expire_stale_blocks()

    pihole.remove_from_denylist.assert_not_called()
    state.delete_threat_domains.assert_not_called()


def test_syncer_touches_last_seen_for_fetched_feed_domains():
    """Every domain seen in a feed refreshes last_seen, even if already known."""
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.side_effect = lambda d: d == "known.ru"
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_feed", return_value=["known.ru", "new.ru"]):
        syncer._sync_one_feed(syncer._feeds[0])

    state.touch_threat_domains.assert_called_once_with(["known.ru", "new.ru"])


def test_syncer_cycle_runs_expiry():
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    state.get_popularity_rank.return_value = None
    state.hours_since_last_sync.return_value = 1.0
    state.get_expired_threat_domains.return_value = []
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_feed", return_value=[]):
        syncer._sync_all_feeds()

    state.get_expired_threat_domains.assert_called_once()


def test_syncer_blocks_full_hostname_on_shared_hosting_despite_popular_apex():
    """evil.github.io: github.io is Tranco-popular, but the subdomain is
    attacker-controlled user content — block the FULL hostname."""
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    state.get_popularity_rank.side_effect = lambda apex: 90 if apex == "github.io" else None
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        feeds=[{"name": "OpenPhish", "url": "http://feed", "category": "PHISHING"}],
    )

    with patch("syncer.fetch_feed", return_value=["evil.github.io"]), \
         patch("syncer.get_shared_hosting_suffixes", return_value={"github.io"}):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 1
    pihole.add_to_denylist.assert_called_once_with(
        ["evil.github.io"], comment="TI:PHISHING:OpenPhish"
    )


def test_syncer_shared_hosting_bypasses_rule_score_threshold():
    """Low-lexical-score subdomain on shared hosting still blocked — the feed
    listing plus attacker-controlled subdomain is the evidence."""
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    state.get_popularity_rank.return_value = None
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        feeds=[{"name": "OpenPhish", "url": "http://feed", "category": "PHISHING"}],
    )

    # "blog.pages.dev" scores near zero lexically — would fail RULE_SCORE_THRESHOLD
    with patch("syncer.fetch_feed", return_value=["blog.pages.dev"]), \
         patch("syncer.get_shared_hosting_suffixes", return_value={"pages.dev"}):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 1
    pihole.add_to_denylist.assert_called_once_with(
        ["blog.pages.dev"], comment="TI:PHISHING:OpenPhish"
    )


def test_syncer_never_blocks_shared_hosting_provider_apex_itself():
    """Feed listing the provider apex (github.io) must never block the provider."""
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    state.get_popularity_rank.return_value = None
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_feed", return_value=["github.io"]), \
         patch("syncer.get_shared_hosting_suffixes", return_value={"github.io"}):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 0
    pihole.add_to_denylist.assert_not_called()
    logged = {c.kwargs["domain"]: c.kwargs["blocked"] for c in state.log_classification.call_args_list}
    assert logged["github.io"] is False


def test_syncer_syncs_psl_private_suffixes_when_due():
    state = MagicMock()
    state.hours_since_last_sync.return_value = None  # never synced
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_psl_private_suffixes", return_value={"github.io", "pages.dev"}) as fetch:
        syncer._sync_shared_hosting()

    fetch.assert_called_once()
    state.replace_shared_hosting_suffixes.assert_called_once_with({"github.io", "pages.dev"})


def test_syncer_skips_psl_sync_when_fresh():
    state = MagicMock()
    state.hours_since_last_sync.return_value = 1.0
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_psl_private_suffixes") as fetch:
        syncer._sync_shared_hosting()

    fetch.assert_not_called()


def test_syncer_empty_psl_fetch_keeps_existing_suffixes():
    state = MagicMock()
    state.hours_since_last_sync.return_value = None
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_psl_private_suffixes", return_value=set()):
        syncer._sync_shared_hosting()

    state.replace_shared_hosting_suffixes.assert_not_called()


def test_syncer_syncs_asn_drop_when_due():
    state = MagicMock()
    state.hours_since_last_sync.return_value = None
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_asn_drop", return_value={205112, 401199}) as fetch:
        syncer._sync_asn_drop()

    fetch.assert_called_once()
    state.replace_bad_asns.assert_called_once_with({205112, 401199})


def test_syncer_skips_asn_drop_sync_when_fresh():
    state = MagicMock()
    state.hours_since_last_sync.return_value = 1.0
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_asn_drop") as fetch:
        syncer._sync_asn_drop()

    fetch.assert_not_called()


def test_syncer_empty_asn_drop_fetch_keeps_existing_list():
    state = MagicMock()
    state.hours_since_last_sync.return_value = None
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    with patch("syncer.fetch_asn_drop", return_value=set()):
        syncer._sync_asn_drop()

    state.replace_bad_asns.assert_not_called()


def test_syncer_marks_skipped_domains_known_to_stop_relogging():
    """Score-skipped feed domains marked known: no re-extraction or duplicate
    classification rows on every 6h cycle."""
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    state.get_popularity_rank.return_value = None
    pihole = MagicMock()
    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        feeds=[{"name": "OpenPhish", "url": "http://feed", "category": "PHISHING"}],
    )

    with patch("syncer.fetch_feed", return_value=["google.com"]):
        syncer._sync_one_feed(syncer._feeds[0])

    pihole.add_to_denylist.assert_not_called()
    state.bulk_mark_threat_domains.assert_called_once_with(["google.com"], feed="OpenPhish")


def test_syncer_expiry_logs_unblock_verdict():
    """Expiry must overwrite the stale blocked=True verdict so subdomain dedup
    stops auto-blocking under an expired apex."""
    state = MagicMock()
    state.get_expired_threat_domains.return_value = ["stale.ru"]
    pihole = MagicMock()
    pihole.remove_from_denylist.return_value = 1
    syncer = _make_syncer(state=state, pihole=pihole)

    syncer._expire_stale_blocks()

    call = state.log_classification.call_args
    assert call.kwargs["domain"] == "stale.ru"
    assert call.kwargs["blocked"] is False


def test_syncer_prunes_state_db_when_due():
    state = MagicMock()
    state.hours_since_last_sync.return_value = None
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    syncer._prune_state()

    state.prune_old_data.assert_called_once()


def test_syncer_skips_prune_when_recent():
    state = MagicMock()
    state.hours_since_last_sync.return_value = 1.0
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)

    syncer._prune_state()

    state.prune_old_data.assert_not_called()


def test_psl_sync_invalidates_shared_hosting_cache():
    import shared_hosting
    state = MagicMock()
    state.hours_since_last_sync.return_value = None
    pihole = MagicMock()
    syncer = _make_syncer(state=state, pihole=pihole)
    shared_hosting._SUFFIX_CACHE.update(loaded_at=9e12, suffixes={"stale.example"})

    with patch("syncer.fetch_psl_private_suffixes", return_value={"github.io"}):
        syncer._sync_shared_hosting()

    assert shared_hosting._SUFFIX_CACHE["suffixes"] is None  # cache invalidated
