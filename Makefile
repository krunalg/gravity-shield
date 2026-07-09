.PHONY: help install test clean setup daemon daemon-start daemon-stop daemon-status logs

VENV := .venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest

help:
	@echo "Pi-hole AI Guardian - Makefile targets:"
	@echo ""
	@echo "  make install         Install dependencies in venv"
	@echo "  make test            Run full test suite"
	@echo "  make setup           Run interactive setup wizard"
	@echo "  make daemon-start    Start systemd daemon"
	@echo "  make daemon-stop     Stop systemd daemon"
	@echo "  make daemon-status   Check daemon status"
	@echo "  make logs            Tail daemon logs"
	@echo "  make clean           Remove venv and caches"
	@echo ""

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install -q requests==2.32.3 watchdog==4.0.1 pytest

test: install
	$(PYTEST) tests/ -v

setup: install
	@bash setup.sh

clean:
	rm -rf $(VENV) .pytest_cache __pycache__ tests/__pycache__ *.pyc
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

daemon-start:
	@if [ -z "$$SUDO_USER" ]; then \
		echo "ERROR: Must have sudo access"; exit 1; \
	fi
	@if [ ! -f "config_local.py" ]; then \
		echo "ERROR: config_local.py not found. Run 'make setup' first"; exit 1; \
	fi
	@SSH_USER=$$(python3 -c "from config_local import SSH_USER; print(SSH_USER)"); \
	sudo systemctl start pihole-ai-$$SSH_USER || echo "Daemon start failed"

daemon-stop:
	@if [ -z "$$SUDO_USER" ]; then \
		echo "ERROR: Must have sudo access"; exit 1; \
	fi
	@SSH_USER=$$(python3 -c "from config_local import SSH_USER; print(SSH_USER)"); \
	sudo systemctl stop pihole-ai-$$SSH_USER || echo "Daemon stop failed"

daemon-status:
	@if [ ! -f "config_local.py" ]; then \
		echo "ERROR: config_local.py not found"; exit 1; \
	fi
	@SSH_USER=$$(python3 -c "from config_local import SSH_USER; print(SSH_USER)"); \
	sudo systemctl status pihole-ai-$$SSH_USER

logs:
	@if [ ! -f "config_local.py" ]; then \
		echo "ERROR: config_local.py not found"; exit 1; \
	fi
	@INSTALL_DIR=$$(python3 -c "from config_local import INSTALL_DIR; print(INSTALL_DIR)"); \
	tail -f $$INSTALL_DIR/logs/pihole-ai.log
