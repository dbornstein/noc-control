#!/bin/bash

set -e  # Exit on any error for safe updates

echo "Starting NOC Agent code update (for PubNub/AWS IoT command relay to Magewell decoders)..."

# Step 1: Pull latest from git (updates noc-agent.py with your mods, e.g., stream URL handling from TAG cron)
echo "Pulling latest code..."
sudo -u noc-agent bash -c "cd /opt/noc-agent/src && git pull origin main"

# Step 2: Reinstall editable package (refreshes venv with new logic for REST to TV controllers)
echo "Updating package in venv..."
sudo -u noc-agent bash -c "source /opt/noc-agent/venv/bin/activate && cd /opt/noc-agent/src && pip install -e . --upgrade"

# Step 3: Restart service (applies changes; systemd auto-restarts on failure for HA resilience)
echo "Restarting service..."
sudo systemctl restart noc-agent

# Step 4: Verify (status and tail logs for startup flow: config pull from MongoDB, PubNub subscribe)
echo "Verifying service..."
sudo systemctl status noc-agent --no-pager -l
echo "Tailing recent logs (Ctrl+C to exit)..."
sudo journalctl -u noc-agent -f --lines=20

echo "Update complete! Agent now running latest code for NOC TV control"