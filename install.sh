#!/bin/bash

# cd /tmp  # Or clone your repo here
# git clone https://github.com/dbornstein/noc-control.git noc-agent-src

sudo adduser --system --group --no-create-home noc-agent

sudo mkdir -p /opt/noc-agent
sudo chown noc-agent:noc-agent /opt/noc-agent
sudo -u noc-agent python3 -m venv /opt/noc-agent/venv3

cd /tmp/noc-agent-src
pip install -e .  # Editable install for easy updates
deactivate

