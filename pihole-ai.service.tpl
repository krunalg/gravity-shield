[Unit]
Description=Pi-hole AI Guardian — AI domain classifier + threat intel sync
After=network-online.target pihole-FTL.service ollama.service
Wants=network-online.target
Requires=pihole-FTL.service

[Service]
Type=simple
User=$SSH_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python daemon.py
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
