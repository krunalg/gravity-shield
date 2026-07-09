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

from pihole_client import PiholeClient, extract_domains_from_lines
from classifier import DomainClassifier
from domain_policy import should_skip_classification
from state_db import StateDB

logger = logging.getLogger(__name__)

CLASSIFY_QUEUE_SIZE = 200


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

    def stop(self):
        self._stop_event.set()

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

    def _handle_domain(self, domain: str):
        result = self._classifier.classify(domain)

        self._state_db.log_classification(
            domain=domain,
            category=result.category,
            confidence=result.confidence,
            reason=result.reason,
            blocked=result.should_block,
            features=result.features,
        )

        if result.should_block:
            comment = f"AI:{result.category}:{result.confidence:.2f}"
            added = self._pihole.add_to_denylist([domain], comment=comment)
            if added:
                logger.warning(
                    f"AUTO-BLOCKED {domain} | {result.category} "
                    f"({result.confidence:.0%}) | {result.reason}"
                )


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
        self._tail_log()

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
                lines = f.readlines()
                if lines:
                    self._process_lines(lines)
                else:
                    time.sleep(self._poll_interval)

    def _process_lines(self, lines: list[str]):
        domains = extract_domains_from_lines(lines)
        if not domains:
            return

        domains = list(dict.fromkeys(d for d in domains if not should_skip_classification(d)))
        new_domains = self._state_db.filter_unseen(domains)

        for domain in new_domains:
            self._state_db.mark_domain_seen(domain)
            try:
                self._queue.put_nowait(domain)
                logger.debug(f"Queued {domain} (queue size: {self._queue.qsize()})")
            except queue.Full:
                logger.warning(f"Classify queue full ({CLASSIFY_QUEUE_SIZE}), dropping {domain}")
