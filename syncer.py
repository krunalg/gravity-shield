from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import threading
import time

from classifier import DomainClassifier
from threat_intel import fetch_feed
from pihole_client import PiholeClient
from state_db import StateDB

logger = logging.getLogger(__name__)


class ThreatIntelSyncer(threading.Thread):
    def __init__(self,
                 state_db: StateDB,
                 pihole_client: PiholeClient,
                 classifier: DomainClassifier = None,
                 feeds: list[dict] = None,
                 interval_hours: float = THREAT_INTEL_INTERVAL_HOURS):
        super().__init__(daemon=True, name="ThreatIntelSyncer")
        self._state_db = state_db
        self._pihole = pihole_client
        self._classifier = classifier
        self._feeds = feeds or THREAT_INTEL_FEEDS
        self._interval_seconds = interval_hours * 3600
        self._stop_event = threading.Event()

    def run(self):
        logger.info(
            f"ThreatIntelSyncer started — syncing every {self._interval_seconds/3600:.0f}h, "
            f"{len(self._feeds)} feeds configured"
        )
        self._sync_all_feeds()
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._interval_seconds)
            if not self._stop_event.is_set():
                self._sync_all_feeds()

    def stop(self):
        self._stop_event.set()

    def _sync_all_feeds(self):
        logger.info("Starting threat intel sync cycle")
        total_added = 0
        for feed_cfg in self._feeds:
            added = self._sync_one_feed(feed_cfg)
            total_added += added
        logger.info(f"Threat intel sync complete — {total_added} new domains added across all feeds")

    def _sync_one_feed(self, feed_cfg: dict) -> int:
        name = feed_cfg.get("name", feed_cfg["url"])
        category = feed_cfg.get("category", "THREAT")

        domains = fetch_feed(feed_cfg)
        if not domains:
            logger.info(f"Feed {name}: 0 domains fetched (empty or error)")
            self._state_db.log_sync_run(feed_name=name, domains_added=0, domains_skipped=0)
            return 0

        new_domains = [
            d for d in domains
            if not self._state_db.is_threat_domain_known(d)
        ]
        skipped = len(domains) - len(new_domains)

        if not new_domains:
            logger.info(f"Feed {name}: {len(domains)} domains, all already known")
            self._state_db.log_sync_run(feed_name=name, domains_added=0, domains_skipped=skipped)
            return 0

        verified_domains = self._verify_domains(new_domains, source=name, category=category)
        if not verified_domains:
            logger.info(f"Feed {name}: no domains passed model verification")
            self._state_db.log_sync_run(feed_name=name, domains_added=0, domains_skipped=skipped)
            return 0

        comment = f"TI:{category}:{name[:30]}"
        added = self._pihole.add_to_denylist(verified_domains, comment=comment)

        self._state_db.bulk_mark_threat_domains(verified_domains, feed=name)

        logger.info(f"Feed {name}: added {added} new domains, skipped {skipped} known")
        self._state_db.log_sync_run(feed_name=name, domains_added=added, domains_skipped=skipped)
        return added

    def _verify_domains(self, domains: list[str], source: str, category: str) -> list[str]:
        if not self._classifier:
            logger.warning(f"Feed {source}: classifier unavailable, refusing to auto-block {len(domains)} domains")
            return []

        verified = []
        for domain in domains:
            result = self._classifier.classify(
                domain,
                threat_context={
                    "feed_source": source,
                    "ioc_category": category,
                    "urlhaus_hit": source.lower() == "urlhaus",
                },
            )
            self._state_db.log_classification(
                domain=domain,
                category=result.category,
                confidence=result.confidence,
                reason=f"Threat intel source {source}: {result.reason}",
                blocked=result.should_block,
                features=result.features,
            )
            if result.should_block:
                verified.append(domain)
            else:
                logger.info(
                    f"Feed {source}: skipped {domain} after model verification "
                    f"({result.category} {result.confidence:.0%})"
                )
        return verified
