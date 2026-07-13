from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import os
import queue
import threading
import time

from brands import get_brand_map
from asn_reputation import get_domain_asn
from rdap import get_domain_age_days
from tls_cert import get_cert_info
from shared_hosting import get_shared_hosting_suffixes, shared_hosting_provider
from pihole_client import PiholeClient, extract_domains_from_lines
from classifier import DomainClassifier
from domain_policy import should_skip_classification
from state_db import StateDB

logger = logging.getLogger(__name__)

CLASSIFY_QUEUE_SIZE = 500


class ClassifierWorker(threading.Thread):
    """Consumes domains from the queue and classifies them one at a time via Ollama."""

    def __init__(self,
                 classify_queue: queue.Queue,
                 classifier: DomainClassifier,
                 state_db: StateDB,
                 pihole_client: PiholeClient):
        super().__init__(daemon=True, name="ClassifierWorker")
        self._queue = classify_queue
        self._classifier = classifier
        self._state_db = state_db
        self._pihole = pihole_client
        self._stop_event = threading.Event()
        self._brands: dict[str, str] | None = None
        self._brands_loaded_at = 0.0

    def stop(self):
        self._stop_event.set()

    def _get_brands(self) -> dict[str, str]:
        if self._brands is None or time.time() - self._brands_loaded_at > BRAND_MAP_REFRESH_SECONDS:
            self._brands = get_brand_map(self._state_db)
            self._brands_loaded_at = time.time()
        return self._brands

    def run(self):
        logger.info("ClassifierWorker started")
        while not self._stop_event.is_set():
            try:
                domain = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._handle_domain(domain)
            except Exception as e:
                logger.error(f"ClassifierWorker error for {domain}: {e}", exc_info=True)
            finally:
                self._queue.task_done()
        logger.info("ClassifierWorker stopped")

    def _handle_domain(self, domain: str):
        from features.extractor import extract
        from features.lexical import registered_domain, registered_domain_private

        # Subdomain deduplication: if the apex domain was already blocked,
        # block this subdomain directly without an Ollama call. Keyed on the
        # PSL-private-aware apex so a blocked evil.github.io covers its
        # subdomains without ever keying on the provider (github.io).
        apex = registered_domain(domain)
        dedup_apex = registered_domain_private(domain)
        if dedup_apex and dedup_apex != domain:
            apex_verdict = self._state_db.get_last_verdict(dedup_apex)
            if apex_verdict and apex_verdict["blocked"]:
                logger.info(f"Subdomain {domain} → apex {dedup_apex} already blocked, blocking directly")
                try:
                    self._pihole.add_to_denylist([domain], comment=f"AI:SUBDOMAIN:{dedup_apex}")
                except Exception as e:
                    logger.error(f"Failed to block subdomain {domain}: {e}", exc_info=True)
                return

        # Shared-hosting detection: subdomains on user-content platforms are
        # owned by untrusted users, so the provider's popularity or age must
        # not vouch for them.
        provider = None
        try:
            match = shared_hosting_provider(domain, get_shared_hosting_suffixes(self._state_db))
            if match and domain.rstrip(".").lower() != match:
                provider = match
        except Exception as e:
            logger.warning(f"Shared-hosting check failed for {domain}: {e}")

        # Popularity allowlist: established apex domains (Tranco rank within
        # threshold) skip LLM classification — unless a threat feed knows them
        # or the hostname is user content on a shared host.
        try:
            rank = self._state_db.get_popularity_rank(apex)
            if rank is not None and provider:
                logger.info(f"{domain}: apex {apex} popular (rank={rank}) but hostname is user content on shared host {provider} — classifying")
            elif rank is not None and not (
                self._state_db.is_threat_domain_known(domain)
                or self._state_db.is_threat_domain_known(apex)
            ):
                logger.info(f"Allowed {domain} via popularity allowlist (apex {apex} rank={rank}) — skipped LLM")
                self._state_db.log_classification(
                    domain=domain,
                    category="SAFE",
                    confidence=1.0,
                    reason=f"Popularity allowlist: apex {apex} rank={rank}",
                    blocked=False,
                )
                return
        except Exception as e:
            logger.error(f"Popularity check failed for {domain}: {e}", exc_info=True)

        brands = self._get_brands()
        try:
            features = extract(domain, brands=brands, shared_hosting_provider=provider)
        except Exception as e:
            logger.error(f"Feature extraction failed for {domain}: {e}", exc_info=True)
            return

        rule_score = features["rules"]["rule_score"]

        if rule_score < RULE_PREFILTER_THRESHOLD:
            logger.info(f"Allowed {domain} via rule pre-filter (rule_score={rule_score}<{RULE_PREFILTER_THRESHOLD}) — skipped LLM")
            try:
                self._state_db.log_classification(
                    domain=domain,
                    category="SAFE",
                    confidence=1.0,
                    reason=f"Rule pre-filter: score={rule_score} below threshold={RULE_PREFILTER_THRESHOLD}",
                    blocked=False,
                    features=features,
                )
            except Exception as e:
                logger.error(f"Failed to log pre-filter classification for {domain}: {e}", exc_info=True)
            return

        # RDAP age lookup only for domains that reach the LLM path — network
        # call, so pre-filtered domains never trigger it. Fail-open: age=None.
        # Skipped on shared hosting: the provider apex's age says nothing
        # about the subdomain owner.
        age_days = None
        if RDAP_ENABLED and not provider:
            try:
                age_days = get_domain_age_days(apex or domain, self._state_db)
                if age_days is not None:
                    logger.info(f"RDAP: {apex or domain} is {age_days} days old")
            except Exception as e:
                logger.warning(f"RDAP age lookup failed for {domain}: {e}")

        # ASN reputation: like RDAP, network lookups only on the LLM path.
        # Fail-open: asn_info=None means "no signal".
        asn_info = None
        if ASN_REPUTATION_ENABLED:
            try:
                asn = get_domain_asn(domain, self._state_db)
                if asn is not None:
                    flagged = bool(self._state_db.is_bad_asn(asn))
                    asn_info = {"asn": asn, "flagged": flagged}
                    if flagged:
                        logger.warning(f"{domain}: hosted in Spamhaus DROP-listed AS{asn}")
            except Exception as e:
                logger.warning(f"ASN lookup failed for {domain}: {e}")

        # TLS analysis is opt-in: a live handshake connects to the suspected
        # host from this machine's IP. Fail-open: tls_info=None.
        tls_info = None
        if TLS_ANALYSIS_ENABLED:
            try:
                tls_info = get_cert_info(domain, self._state_db)
            except Exception as e:
                logger.warning(f"TLS analysis failed for {domain}: {e}")

        try:
            result = self._classifier.classify(domain, brands=brands, domain_age_days=age_days,
                                               shared_hosting_provider=provider,
                                               asn_info=asn_info,
                                               tls_info=tls_info)
        except Exception as e:
            logger.error(f"Classifier failed for {domain}: {e}", exc_info=True)
            return

        try:
            self._state_db.log_classification(
                domain=domain,
                category=result.category,
                confidence=result.confidence,
                reason=result.reason,
                blocked=result.should_block,
                features=result.features,
            )
        except Exception as e:
            logger.error(f"Failed to log classification for {domain}: {e}", exc_info=True)

        if result.should_block:
            try:
                comment = f"AI:{result.category}:{result.confidence:.2f}"
                added = self._pihole.add_to_denylist([domain], comment=comment)
                if added:
                    logger.warning(
                        f"AUTO-BLOCKED {domain} | {result.category} "
                        f"({result.confidence:.0%}) | {result.reason}"
                    )
            except Exception as e:
                logger.error(f"Failed to block {domain} in Pi-hole: {e}", exc_info=True)


class DomainWatcher(threading.Thread):
    """Tails Pi-hole FTL log and enqueues new domains for classification."""

    def __init__(self,
                 state_db: StateDB,
                 classify_queue: queue.Queue,
                 log_path: str = FTL_LOG_PATH,
                 poll_interval: float = 2.0):
        super().__init__(daemon=True, name="DomainWatcher")
        self._state_db = state_db
        self._queue = classify_queue
        self._log_path = log_path
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info(f"DomainWatcher started, tailing {self._log_path}")
        while not self._stop_event.is_set():
            try:
                self._tail_log()
            except Exception as e:
                logger.error(f"DomainWatcher error: {e}", exc_info=True)
                if not self._stop_event.is_set():
                    logger.info("DomainWatcher restarting tail in 5s")
                    time.sleep(5)
        logger.info("DomainWatcher stopped")

    def _tail_log(self):
        while not self._stop_event.is_set():
            if os.path.exists(self._log_path):
                break
            logger.warning(f"Log file not found: {self._log_path}, retrying in 10s")
            time.sleep(10)

        with open(self._log_path, "r") as f:
            f.seek(0, 2)
            logger.info("DomainWatcher now reading new log lines")

            while not self._stop_event.is_set():
                try:
                    lines = f.readlines()
                except OSError as e:
                    logger.warning(f"Log read error (rotation?): {e} — reopening")
                    return  # exits _tail_log, run() will restart it
                if lines:
                    self._process_lines(lines)
                else:
                    time.sleep(self._poll_interval)

    def _process_lines(self, lines: list[str]):
        try:
            domains = extract_domains_from_lines(lines)
        except Exception as e:
            logger.error(f"Failed to parse log lines: {e}", exc_info=True)
            return

        if not domains:
            return

        domains = list(dict.fromkeys(d for d in domains if not should_skip_classification(d)))

        try:
            new_domains = self._state_db.filter_unseen(domains)
        except Exception as e:
            logger.error(f"StateDB filter_unseen failed: {e}", exc_info=True)
            return

        for domain in new_domains:
            # Enqueue first, mark seen only on success — a dropped domain must
            # be retried on its next query, not silenced for the whole TTL.
            try:
                self._queue.put_nowait(domain)
            except queue.Full:
                logger.warning(f"Classify queue full ({CLASSIFY_QUEUE_SIZE}), dropping {domain}")
                continue
            logger.debug(f"Queued {domain} (queue size: {self._queue.qsize()})")
            try:
                self._state_db.mark_domain_seen(domain)
            except Exception as e:
                logger.error(f"Failed to mark {domain} as seen: {e}", exc_info=True)
