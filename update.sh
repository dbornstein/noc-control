#!/bin/bash

echo "Starting update" 

export PATH=/usr/bin:$PATH

# Parse flags (for silent Python calls)
SILENT=false
while [[ $# -gt 0 ]]; do
  case $1 in
    --silent) SILENT=true; shift ;;
    *) echo "Unknown option $1"; exit 1 ;;
  esac
done

set -e  # Exit on error

LOG_FILE="/var/log/noc-agent-update.log"
echo "$(date): Starting NOC Agent update..." >> "$LOG_FILE"

# Step 1: Pull latest from git (updates noc-agent.py with TAG stream URL handling)
echo "Pulling latest code..." | tee -a "$LOG_FILE"
sudo -u noc-agent bash -c "cd /opt/noc-agent/src && git pull origin main" >> "$LOG_FILE" 2>&1

# Step 2: Reinstall editable package (refreshes venv for REST to TV controllers)
echo "Updating package in venv..." | tee -a "$LOG_FILE"
sudo -u noc-agent bash -c "source /opt/noc-agent/venv/bin/activate && cd /opt/noc-agent/src && pip install -e . --upgrade" >> "$LOG_FILE" 2>&1

# Step 3: Restart service (systemd auto-restarts; HA peer covers brief downtime)
echo "Restarting service..." | tee -a "$LOG_FILE"
sudo systemctl restart noc-agent >> "$LOG_FILE" 2>&1

# Step 4: Quick verify (non-blocking; skip tail in silent mode)
if [[ "$SILENT" == false ]]; then
  echo "Service status:" | tee -a "$LOG_FILE"
  sudo systemctl status noc-agent --no-pager -l >> "$LOG_FILE" 2>&1
  echo "Recent logs (last 20 lines):" | tee -a "$LOG_FILE"
  sudo journalctl -u noc-agent --lines=20 >> "$LOG_FILE" 2>&1
  # In manual mode, you can add tail -f here if desired, but it would block
else
  # Silent: Just check active status
  if sudo systemctl is-active --quiet noc-agent; then
    echo "$(date): Service active post-update." >> "$LOG_FILE"
  else
    echo "$(date): Service failed post-update—check logs." >> "$LOG_FILE"
  fi
fi

echo "$(date): Update complete! Agent ready for PubNub commands to Magewell decoders." >> "$LOG_FILE"