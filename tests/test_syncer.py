import os, sys
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from classifier import ClassificationResult
from syncer import ThreatIntelSyncer


def _classifier_with_results(results):
    clf = MagicMock()
    clf.classify.side_effect = results
    return clf


def test_syncer_blocks_only_model_verified_threats(tmp_path):
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1
    classifier = _classifier_with_results([
        ClassificationResult("evil.com", "MALWARE", 0.95, "known malware", True),
        ClassificationResult("safe.com", "SAFE", 0.99, "legitimate", False),
    ])

    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        classifier=classifier,
        feeds=[{"name": "URLhaus", "url": "http://feed", "category": "MALWARE"}],
    )

    with patch("syncer.fetch_feed", return_value=["evil.com", "safe.com"]):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 1
    pihole.add_to_denylist.assert_called_once_with(["evil.com"], comment="TI:MALWARE:URLhaus")
    state.bulk_mark_threat_domains.assert_called_once_with(["evil.com"], feed="URLhaus")
    assert state.log_classification.call_count == 2


def test_syncer_does_not_block_when_classifier_is_unavailable():
    state = MagicMock()
    state.is_threat_domain_known.return_value = False
    pihole = MagicMock()

    syncer = ThreatIntelSyncer(
        state_db=state,
        pihole_client=pihole,
        classifier=None,
        feeds=[{"name": "URLhaus", "url": "http://feed", "category": "MALWARE"}],
    )

    with patch("syncer.fetch_feed", return_value=["evil.com"]):
        added = syncer._sync_one_feed(syncer._feeds[0])

    assert added == 0
    pihole.add_to_denylist.assert_not_called()
    state.bulk_mark_threat_domains.assert_not_called()
