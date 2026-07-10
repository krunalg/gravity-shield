.PHONY: help install test clean setup daemon-start daemon-stop daemon-restart daemon-status logs fix-permissions reset re-setup

VENV := .venv
PYTHON := $(VENV)/bin/python3
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest

help:
	@echo "Pi-hole AI Guardian - Makefile targets:"
	@echo ""
	@echo "  Setup & Install:"
	@echo "    make install         Install dependencies in venv"
	@echo "    make test            Run full test suite"
	@echo "    make setup           Run interactive setup wizard"
	@echo ""
	@echo "  Daemon Management:"
	@echo "    make daemon-start    Start systemd daemon"
	@echo "    make daemon-stop     Stop systemd daemon"
	@echo "    make daemon-restart  Restart systemd daemon"
	@echo "    make daemon-status   Check daemon status"
	@echo "    make logs            Tail daemon logs"
	@echo ""
	@echo "  Reset & Cleanup:"
	@echo "    make reset           Stop daemon, clean config/state/logs"
	@echo "    make re-setup        Reset and run setup wizard"
	@echo "    make fix-permissions Re-apply Pi-hole file ACLs (run after pihole -g)"
	@echo "    make clean           Remove venv and caches"
	@echo ""

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install -q -e ".[dev]"

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

daemon-restart:
	@if [ -z "$$SUDO_USER" ]; then \
		echo "ERROR: Must have sudo access"; exit 1; \
	fi
	@SSH_USER=$$(python3 -c "from config_local import SSH_USER; print(SSH_USER)"); \
	sudo systemctl restart pihole-ai-$$SSH_USER && echo "✓ Daemon restarted" || echo "Daemon restart failed"

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

reset: daemon-stop
	@echo "Cleaning up old config and state..."
	@STATE_DB=$$(python3 -c "from config_local import STATE_DB_PATH; print(STATE_DB_PATH)" 2>/dev/null || echo "state.db"); \
	rm -f "$$STATE_DB" && echo "Removed $$STATE_DB"
	rm -f config_local.py
	rm -rf logs/*
	@echo "✓ Ready to re-setup"

re-setup: reset
	@echo "Running setup wizard..."
	make setup

fix-permissions:
	@if [ ! -f "config_local.py" ]; then \
		echo "ERROR: config_local.py not found. Run 'make setup' first"; exit 1; \
	fi
	@SSH_USER=$$(python3 -c "from config_local import SSH_USER; print(SSH_USER)"); \
	PIHOLE_DB=$$(python3 -c "from config_local import PIHOLE_DB_PATH; print(PIHOLE_DB_PATH)" 2>/dev/null || echo "/etc/pihole/gravity.db"); \
	FTL_LOG=$$(python3 -c "from config_local import FTL_LOG_PATH; print(FTL_LOG_PATH)" 2>/dev/null || echo "/var/log/pihole/pihole.log"); \
	echo "Re-applying ACLs for user $$SSH_USER..."; \
	sudo setfacl -m u:$$SSH_USER:rwx /etc/pihole/ && echo "  ✓ /etc/pihole/"; \
	sudo setfacl -m u:$$SSH_USER:rw $$PIHOLE_DB && echo "  ✓ $$PIHOLE_DB"; \
	sudo setfacl -m u:$$SSH_USER:rw /etc/pihole/versions && echo "  ✓ /etc/pihole/versions"; \
	sudo setfacl -m u:$$SSH_USER:rx /var/log/pihole/ && echo "  ✓ /var/log/pihole/"; \
	sudo setfacl -m u:$$SSH_USER:r $$FTL_LOG && echo "  ✓ $$FTL_LOG"; \
	echo "✓ Permissions restored"
