#!/usr/bin/env python3
"""
Pi-hole AI Guardian Daemon
Combines real-time AI domain classification with threat intel sync.
"""
from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import os
import signal
import sys
import time

from state_db import StateDB
from pihole_client import PiholeClient
from ollama_client import OllamaClient
from classifier import DomainClassifier
from watcher import DomainWatcher
from syncer import ThreatIntelSyncer


def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)
    level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    fmt = "%(asctime)s [%(name)s] %(levelname)s %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(os.path.join(LOG_DIR, "pihole-ai.log")),
        ]
    )


def main():
    setup_logging()
    logger = logging.getLogger("daemon")
    logger.info("Pi-hole AI Guardian starting")

    ollama = OllamaClient()
    if not ollama.is_available():
        logger.error("Ollama is not running at localhost:11434 — start with: ollama serve")
        sys.exit(1)

    state = StateDB(STATE_DB_PATH)
    pihole = PiholeClient()
    clf = DomainClassifier(ollama_client=ollama)

    watcher = DomainWatcher(state_db=state, classifier=clf, pihole_client=pihole)
    syncer = ThreatIntelSyncer(state_db=state, pihole_client=pihole, classifier=clf)

    def _shutdown(signum, frame):
        logger.info(f"Received signal {signum}, shutting down")
        watcher.stop()
        syncer.stop()
        pihole.flush_reload()
        state.close()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    watcher.start()
    syncer.start()

    logger.info("Both workers started — daemon running")
    while True:
        time.sleep(60)
        if not watcher.is_alive():
            logger.error("DomainWatcher died — restarting")
            watcher = DomainWatcher(state_db=state, classifier=clf, pihole_client=pihole)
            watcher.start()


if __name__ == "__main__":
    main()
