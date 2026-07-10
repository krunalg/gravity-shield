from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import threading
import time

from classifier import DomainClassifier
from features.extractor import extract
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
        self._check_feed_freshness()
        total_added = 0
        for feed_cfg in self._feeds:
            try:
                added = self._sync_one_feed(feed_cfg)
                total_added += added
            except Exception as e:
                logger.error(f"Feed {feed_cfg.get('name', feed_cfg.get('url'))}: unhandled error during sync: {e}", exc_info=True)
        logger.info(f"Threat intel sync complete — {total_added} new domains added across all feeds")

    def _check_feed_freshness(self):
        for feed_cfg in self._feeds:
            name = feed_cfg.get("name", feed_cfg["url"])
            try:
                hours = self._state_db.hours_since_last_sync(name)
                if hours is None:
                    logger.info(f"Feed {name}: never synced before")
                elif isinstance(hours, (int, float)) and hours > FEED_STALENESS_WARN_HOURS:
                    logger.warning(f"Feed {name}: last synced {hours:.1f}h ago (threshold: {FEED_STALENESS_WARN_HOURS}h) — possible network or config issue")
            except Exception as e:
                logger.error(f"Feed {name}: freshness check failed: {e}")

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
            logger.info(f"Feed {name}: no domains passed rule verification")
            self._state_db.log_sync_run(feed_name=name, domains_added=0, domains_skipped=skipped)
            return 0

        comment = f"TI:{category}:{name[:30]}"
        added = self._pihole.add_to_denylist(verified_domains, comment=comment)

        self._state_db.bulk_mark_threat_domains(verified_domains, feed=name)

        logger.info(f"Feed {name}: added {added} new domains, skipped {skipped} known")
        self._state_db.log_sync_run(feed_name=name, domains_added=added, domains_skipped=skipped)
        return added

    def _verify_domains(self, domains: list[str], source: str, category: str) -> list[str]:
        """
        Verify feed domains using deterministic feature extraction + rule scoring only.
        Ollama is not used here — feed classification at scale (10k+ domains) is impractical
        with a local LLM. Ollama is reserved for real-time DNS query classification in watcher.py.
        """
        is_urlhaus = source.lower() == "urlhaus"
        threat_context = {
            "feed_source": source,
            "ioc_category": category,
            "urlhaus_hit": is_urlhaus,
        }
        verified = []
        skipped_count = 0
        for domain in domains:
            features = extract(domain, threat_context=threat_context)
            rule_score = features["rules"]["rule_score"]
            # URLhaus hit alone scores 100 — always passes.
            # Other feeds: require RULE_SCORE_THRESHOLD.
            passes = is_urlhaus or rule_score >= RULE_SCORE_THRESHOLD
            self._state_db.log_classification(
                domain=domain,
                category=category,
                confidence=1.0 if is_urlhaus else min(rule_score / 100, 1.0),
                reason=f"Feed {source} rule-based: score={rule_score} urlhaus={is_urlhaus}",
                blocked=passes,
                features=features,
            )
            if passes:
                verified.append(domain)
            else:
                skipped_count += 1
                logger.debug(f"Feed {source}: rule-skipped {domain} (score={rule_score})")
        logger.info(
            f"Feed {source}: rule-verified {len(verified)} domains, "
            f"rule-skipped {skipped_count} (score<{RULE_SCORE_THRESHOLD})"
        )
        return verified
