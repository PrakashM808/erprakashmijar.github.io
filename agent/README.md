# PM::OFFSEC Device Agent

Lightweight Python agent that runs on employee devices and reports security status to the PM::OFFSEC dashboard.

## Quick Start

```bash
# 1. Download
curl -O https://erprakashmijar.com/agent/pm_offsec_agent.py

# 2. Run with your token (get it from dashboard → Devices → Add Device)
python3 pm_offsec_agent.py --token YOUR_AGENT_TOKEN

# 3. Or run a one-time scan
python3 pm_offsec_agent.py --token YOUR_AGENT_TOKEN --scan
```

## What It Checks
- SSH configuration (root login, password auth)
- Firewall status (ufw/iptables)
- Dangerous open ports (MySQL, Redis, MongoDB, etc.)
- Package update status

## Install as Linux Service

```bash
sudo tee /etc/systemd/system/pm-offsec.service << EOF
[Unit]
Description=PM::OFFSEC Security Agent
After=network.target

[Service]
ExecStart=python3 /opt/pm_offsec_agent.py --token YOUR_TOKEN
Restart=always
User=nobody

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable pm-offsec
sudo systemctl start pm-offsec
```

## Requirements
- Python 3.8+
- No external packages needed (stdlib only)
