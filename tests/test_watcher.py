import os, sys
from unittest.mock import MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from watcher import DomainWatcher


def test_watcher_skips_known_legitimate_meta_hostname():
    state = MagicMock()
    classifier = MagicMock()
    pihole = MagicMock()
    watcher = DomainWatcher(state_db=state, classifier=classifier, pihole_client=pihole)

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] instagram.c10r.instagram.com from 192.168.1.10\n"
    ])

    state.filter_unseen.assert_called_once_with([])
    state.mark_domain_seen.assert_not_called()
    classifier.classify.assert_not_called()
    pihole.add_to_denylist.assert_not_called()


def test_watcher_skips_meta_owned_domain_suffixes():
    state = MagicMock()
    classifier = MagicMock()
    pihole = MagicMock()
    watcher = DomainWatcher(state_db=state, classifier=classifier, pihole_client=pihole)

    watcher._process_lines([
        "Jul 09 22:01:00 dnsmasq[1]: query[A] graph.facebook.com from 192.168.1.10\n",
        "Jul 09 22:01:01 dnsmasq[1]: query[A] edge-mqtt.facebook.com from 192.168.1.10\n",
    ])

    state.filter_unseen.assert_called_once_with([])
    classifier.classify.assert_not_called()
    pihole.add_to_denylist.assert_not_called()
