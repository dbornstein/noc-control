#!/bim/bash

sudo adduser --system --group --no-create-home noc-agent

sudo mkdir -p /opt/noc-agent
sudo chown noc-agent:noc-agent /opt/noc-agent
sudo -u noc-agent python3.13 -m venv /opt/noc-agent/venv

sudo -u noc-agent /opt/noc-agent/venv/bin/activate
cd /tmp  # Or clone your repo here
git clone <your-repo-url> noc-agent-src
cd noc-agent-src
pip install -e .  # Editable install for easy updates
deactivate

