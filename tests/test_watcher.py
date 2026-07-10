import os, sys, queue
from unittest.mock import MagicMock, patch
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from watcher import DomainWatcher, ClassifierWorker


def _make_watcher(state=None):
    state = state or MagicMock()
    state.filter_unseen.return_value = []
    q = queue.Queue()
    watcher = DomainWatcher(state_db=state, classify_queue=q)
    return watcher, q, state


def test_watcher_skips_infra_domains():
    watcher, q, state = _make_watcher()

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] pi.hole from 192.168.1.10\n",
        "Jul 09 22:01:01 dnsmasq[1]: query[A] router.lan from 192.168.1.10\n",
    ])

    state.mark_domain_seen.assert_not_called()
    assert q.empty()


def test_watcher_no_longer_hardcodes_brand_domain_skips():
    """Brand-owned domains are handled by the popularity allowlist at
    classification time, not by a hardcoded skip list at intake."""
    state = MagicMock()
    state.filter_unseen.return_value = ["graph.facebook.com"]
    q = queue.Queue()
    watcher = DomainWatcher(state_db=state, classify_queue=q)

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] graph.facebook.com from 192.168.1.10\n",
    ])

    assert q.get_nowait() == "graph.facebook.com"


def test_watcher_enqueues_new_unseen_domain():
    state = MagicMock()
    state.filter_unseen.return_value = ["evil.xyz"]
    q = queue.Queue()
    watcher = DomainWatcher(state_db=state, classify_queue=q)

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] evil.xyz from 192.168.1.10\n"
    ])

    assert q.get_nowait() == "evil.xyz"
    state.mark_domain_seen.assert_called_once_with("evil.xyz")


def test_watcher_drops_domain_when_queue_full():
    state = MagicMock()
    state.filter_unseen.return_value = ["evil.xyz"]
    q = queue.Queue(maxsize=1)
    q.put("blocker")  # fill the queue
    watcher = DomainWatcher(state_db=state, classify_queue=q)

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] evil.xyz from 192.168.1.10\n"
    ])

    assert q.qsize() == 1  # still just the blocker, evil.xyz was dropped


def _make_worker_state():
    state = MagicMock()
    state.get_popularity_rank.return_value = None
    state.is_threat_domain_known.return_value = False
    state.get_last_verdict.return_value = None
    # Tranco snapshot the worker derives its brand map from
    state.get_top_domains.return_value = {"paypal.com": 30}
    return state

_WORKER_BRANDS = {"paypal": "paypal.com", **__import__("config").EXTRA_BRANDS}


def test_classifier_worker_classifies_and_blocks(tmp_path):
    from classifier import ClassificationResult
    clf = MagicMock()
    # paypa1-secure.xyz: brand(paypal)=+25, suspicious TLD=+10 → rule_score=35, above prefilter
    domain = "paypa1-secure.xyz"
    clf.classify.return_value = ClassificationResult(
        domain, "MALWARE", 0.95, "known malware", True
    )
    state = _make_worker_state()
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    with patch("watcher.get_domain_age_days", return_value=None):
        worker._handle_domain(domain)

    clf.classify.assert_called_once_with(domain, brands=_WORKER_BRANDS, domain_age_days=None)
    state.log_classification.assert_called_once()
    pihole.add_to_denylist.assert_called_once_with([domain], comment="AI:MALWARE:0.95")


def test_classifier_worker_allows_safe_domain():
    from classifier import ClassificationResult
    clf = MagicMock()
    clf.classify.return_value = ClassificationResult(
        "safe.com", "SAFE", 0.99, "legitimate", False
    )
    state = _make_worker_state()
    pihole = MagicMock()

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    # safe.com scores 0 — pre-filtered without Ollama call
    worker._handle_domain("safe.com")

    clf.classify.assert_not_called()
    pihole.add_to_denylist.assert_not_called()
    state.log_classification.assert_called_once()


def test_classifier_worker_prefilter_skips_ollama_for_low_score_domain():
    clf = MagicMock()
    state = _make_worker_state()
    pihole = MagicMock()

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    # bbc.co.uk scores 0 — well below RULE_PREFILTER_THRESHOLD
    worker._handle_domain("bbc.co.uk")

    clf.classify.assert_not_called()
    pihole.add_to_denylist.assert_not_called()
    state.log_classification.assert_called_once()


def test_classifier_worker_skips_ollama_for_popular_apex():
    clf = MagicMock()
    state = _make_worker_state()
    state.get_popularity_rank.return_value = 42
    pihole = MagicMock()

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    worker._handle_domain("oauth2.googleapis.com")

    state.get_popularity_rank.assert_called_once_with("googleapis.com")
    clf.classify.assert_not_called()
    pihole.add_to_denylist.assert_not_called()
    state.log_classification.assert_called_once()
    assert state.log_classification.call_args.kwargs["category"] == "SAFE"


def test_classifier_worker_ignores_popularity_for_threat_feed_domain():
    from classifier import ClassificationResult
    clf = MagicMock()
    domain = "paypa1-secure.xyz"
    clf.classify.return_value = ClassificationResult(
        domain, "PHISHING", 0.95, "feed-listed", True
    )
    state = _make_worker_state()
    state.get_popularity_rank.return_value = 42       # popular apex...
    state.is_threat_domain_known.return_value = True  # ...but threat feed knows it
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    with patch("watcher.get_domain_age_days", return_value=None):
        worker._handle_domain(domain)

    clf.classify.assert_called_once_with(domain, brands=_WORKER_BRANDS, domain_age_days=None)
    pihole.add_to_denylist.assert_called_once()


def test_classifier_worker_passes_rdap_age_to_classifier():
    from classifier import ClassificationResult
    clf = MagicMock()
    domain = "paypa1-secure.xyz"
    clf.classify.return_value = ClassificationResult(
        domain, "PHISHING", 0.95, "new domain", True
    )
    state = _make_worker_state()
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    with patch("watcher.get_domain_age_days", return_value=4) as age:
        worker._handle_domain(domain)

    age.assert_called_once_with("paypa1-secure.xyz", state)
    clf.classify.assert_called_once_with(domain, brands=_WORKER_BRANDS, domain_age_days=4)


def test_classifier_worker_rdap_failure_is_fail_open():
    from classifier import ClassificationResult
    clf = MagicMock()
    domain = "paypa1-secure.xyz"
    clf.classify.return_value = ClassificationResult(
        domain, "SAFE", 0.9, "ok", False
    )
    state = _make_worker_state()
    pihole = MagicMock()

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    with patch("watcher.get_domain_age_days", side_effect=RuntimeError("rdap down")):
        worker._handle_domain(domain)

    clf.classify.assert_called_once_with(domain, brands=_WORKER_BRANDS, domain_age_days=None)
