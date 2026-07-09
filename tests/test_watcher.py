import os, sys, queue
from unittest.mock import MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from watcher import DomainWatcher, ClassifierWorker


def _make_watcher(state=None):
    state = state or MagicMock()
    state.filter_unseen.return_value = []
    q = queue.Queue()
    watcher = DomainWatcher(state_db=state, classify_queue=q)
    return watcher, q, state


def test_watcher_skips_known_legitimate_meta_hostname():
    watcher, q, state = _make_watcher()

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] instagram.c10r.instagram.com from 192.168.1.10\n"
    ])

    state.filter_unseen.assert_called_once_with([])
    state.mark_domain_seen.assert_not_called()
    assert q.empty()


def test_watcher_skips_meta_owned_domain_suffixes():
    watcher, q, state = _make_watcher()

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] graph.facebook.com from 192.168.1.10\n",
        "Jul 09 22:01:01 dnsmasq[1]: query[A] edge-mqtt.facebook.com from 192.168.1.10\n",
    ])

    state.filter_unseen.assert_called_once_with([])
    assert q.empty()


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


def test_classifier_worker_classifies_and_blocks(tmp_path):
    from classifier import ClassificationResult
    clf = MagicMock()
    clf.classify.return_value = ClassificationResult(
        "evil.xyz", "MALWARE", 0.95, "known malware", True
    )
    state = MagicMock()
    pihole = MagicMock()
    pihole.add_to_denylist.return_value = 1

    q = queue.Queue()
    q.put("evil.xyz")

    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    worker._handle_domain("evil.xyz")

    clf.classify.assert_called_once_with("evil.xyz")
    state.log_classification.assert_called_once()
    pihole.add_to_denylist.assert_called_once_with(["evil.xyz"], comment="AI:MALWARE:0.95")


def test_classifier_worker_allows_safe_domain():
    from classifier import ClassificationResult
    clf = MagicMock()
    clf.classify.return_value = ClassificationResult(
        "safe.com", "SAFE", 0.99, "legitimate", False
    )
    state = MagicMock()
    pihole = MagicMock()

    q = queue.Queue()
    worker = ClassifierWorker(classify_queue=q, classifier=clf,
                              state_db=state, pihole_client=pihole)
    worker._handle_domain("safe.com")

    pihole.add_to_denylist.assert_not_called()
    state.log_classification.assert_called_once()
