#!/bin/bash

set -e  # Exit on any error

echo "Starting NOC Agent installation (idempotent mode)..."

# Create system user if it doesn't exist (idempotent)
if ! id -u noc-agent &>/dev/null; then
    echo "Creating system user 'noc-agent'..."
    sudo adduser --system --group --no-create-home noc-agent
else
    echo "System user 'noc-agent' already exists."
fi

# Create installation directory (idempotent)
INSTALL_DIR="/opt/noc-agent"
sudo mkdir -p "$INSTALL_DIR"
sudo chown noc-agent:noc-agent "$INSTALL_DIR"

# Source directory (persistent for editable install)
INSTALL_SRC="$INSTALL_DIR/src"
sudo mkdir -p "$INSTALL_SRC"
sudo chown noc-agent:noc-agent "$INSTALL_SRC"

# Clone or update the repository (idempotent, persistent source)
cd "$INSTALL_SRC"
if [ -d ".git" ]; then
    echo "Repository already cloned, updating to latest..."
    sudo -u noc-agent git pull origin main  # Assumes main branch; adjust if needed
else
    echo "Cloning repository from https://github.com/dbornstein/noc-control.git..."
    sudo -u noc-agent git clone https://github.com/dbornstein/noc-control.git .
fi

# Create virtual environment (idempotent: recreate only if missing or corrupted)
VENV_DIR="$INSTALL_DIR/venv"
if [ ! -d "$VENV_DIR" ] || [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "Creating/Recreating Python virtual environment in $VENV_DIR..."
    sudo rm -rf "$VENV_DIR"  # Clean slate if corrupted
    sudo -u noc-agent python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists and is valid."
fi

# Install/Upgrade the package editable into the venv (idempotent: always reinstall for updates)
# Set HOME to INSTALL_DIR to avoid /nonexistent cache issues for system user
echo "Installing/Updating noc-agent package..."
sudo -u noc-agent bash -c "
    export HOME=$INSTALL_DIR
    source $VENV_DIR/bin/activate
    cd $INSTALL_SRC
    pip install --upgrade pip
    pip install -e . --upgrade  # --upgrade ensures latest deps and code
"

# Copy configuration file (idempotent)
CONFIG_PATH="$INSTALL_DIR/agent_config.json"
echo "Copying agent configuration to $CONFIG_PATH..."
sudo cp "$INSTALL_SRC/agent_config.json" "$CONFIG_PATH"
sudo chown noc-agent:noc-agent "$CONFIG_PATH"  # Ensure ownership

# Prompt for agentId and configId early if empty (before service setup)
echo "Checking agent_config.json for agentId and configId..."
NEEDS_PROMPT=$(python3 -c "
import json
try:
    with open('$CONFIG_PATH', 'r') as f:
        d = json.load(f)
    agent_id = d.get('agentId', '')
    config_id = d.get('configId', '')
    if agent_id == '' or config_id == '':
        print('PROMPT')
    else:
        print('OK')
except Exception as e:
    print('PROMPT')  # Prompt if JSON invalid or missing
" 2>/dev/null)

if [ "$NEEDS_PROMPT" = "PROMPT" ]; then
    echo "Prompting for missing/empty agentId and/or configId..."
    read -p "Enter agentId (e.g., noc-agent-usnj01): " AGENT_ID
    read -p "Enter configId (e.g., noc-config-001): " CONFIG_ID

    # Update JSON using Python (robust: handle missing keys)
    sudo python3 -c "
import json
data = {}
try:
    with open('$CONFIG_PATH', 'r') as f:
        data = json.load(f)
except:
    pass  # Start fresh if invalid

data['agentId'] = '$AGENT_ID'
data['configId'] = '$CONFIG_ID'

with open('$CONFIG_PATH', 'w') as f:
    json.dump(data, f, indent=4)
print('Updated agent_config.json with agentId: $AGENT_ID and configId: $CONFIG_ID')
" || echo "Update failed; check JSON syntax in $CONFIG_PATH"

    sudo chown noc-agent:noc-agent "$CONFIG_PATH"
else
    echo "agentId and configId are already set in $CONFIG_PATH."
fi

# Now validate other config aspects post-prompt
if ! grep -q '"pubnubConfig"' "$CONFIG_PATH" 2>/dev/null || ! grep -q '"subscribeKey"' "$CONFIG_PATH" 2>/dev/null; then
    echo "WARNING: PubNub config (subscribeKey, etc.) missing in $CONFIG_PATH or downloaded agent config. Needed for AWS IoT command relay."
fi
if ! grep -q '"apiEndpoint":' "$CONFIG_PATH" 2>/dev/null || grep -q '"apiEndpoint": *""' "$CONFIG_PATH" 2>/dev/null; then
    echo "WARNING: apiEndpoint missing or empty in $CONFIG_PATH. Required for downloading config from AWS (MongoDB/TAG integration)."
fi

# Copy/Update systemd service (idempotent: overwrite for latest version)
SERVICE_FILE="/etc/systemd/system/noc-agent.service"
echo "Setting up/Updating systemd service..."
sudo cp "$INSTALL_SRC/noc-agent.service" "$SERVICE_FILE"
sudo chown root:root "$SERVICE_FILE"
sudo chmod 644 "$SERVICE_FILE"

# Clean up invalid Restart line (remove inline comment)
sudo sed -i 's/Restart=always.*$/Restart=always/' "$SERVICE_FILE"

# Ensure key [Service] directives for logging, unbuffered output, and working dir
echo "Configuring service for reliable logging and execution..."
sudo bash -c "
    # Add/Ensure StandardOutput and StandardError to journal
    if ! grep -q '^StandardOutput=journal' '$SERVICE_FILE'; then
        sed -i '/^\[Service\]/a StandardOutput=journal' '$SERVICE_FILE'
    fi
    if ! grep -q '^StandardError=journal' '$SERVICE_FILE'; then
        sed -i '/^\[Service\]/a StandardError=journal' '$SERVICE_FILE'
    fi
    # Add/Ensure unbuffered Python output
    if ! grep -q '^Environment=PYTHONUNBUFFERED=1' '$SERVICE_FILE'; then
        sed -i '/^\[Service\]/a Environment=PYTHONUNBUFFERED=1' '$SERVICE_FILE'
    fi
    # Ensure WorkingDirectory for module and includes access
    if ! grep -q '^WorkingDirectory=' '$SERVICE_FILE'; then
        echo 'WorkingDirectory='$INSTALL_SRC | sed -i '/^\[Service\]/a ' - '$SERVICE_FILE'
    else
        sed -i 's|^WorkingDirectory=.*|WorkingDirectory='$INSTALL_SRC'|g' '$SERVICE_FILE'
    fi
    # Ensure ExecStart uses python -m noc_agent (fixes argv passing via __main__)
    sed -i 's|^ExecStart=.*|ExecStart='$VENV_DIR'/bin/python -m noc_agent --agent --config-file '$CONFIG_PATH'|g' '$SERVICE_FILE'
    # Ensure Restart=always is clean
    sed -i 's|^Restart=.*|Restart=always|g' '$SERVICE_FILE'
"

# Copy update.sh to /opt/noc-agent and set permissions (idempotent)
UPDATE_SCRIPT="$INSTALL_DIR/update.sh"
if [ ! -f "$UPDATE_SCRIPT" ] || [ "$INSTALL_SRC/update.sh" -nt "$UPDATE_SCRIPT" ]; then  # Copy if missing or source newer
    echo "Copying update.sh to $UPDATE_SCRIPT..."
    sudo cp "$INSTALL_SRC/update.sh" "$UPDATE_SCRIPT"
    sudo chown root:root "$UPDATE_SCRIPT"
    sudo chmod 755 "$UPDATE_SCRIPT"
    echo "update.sh installed and executable (run with sudo $UPDATE_SCRIPT for code updates)."
else
    echo "update.sh already up to date in $UPDATE_SCRIPT."
fi

# Reload systemd, enable (idempotent), and manage service
echo "Configuring systemd service..."
sudo systemctl daemon-reload
if ! sudo systemctl is-enabled --quiet noc-agent; then
    sudo systemctl enable noc-agent
    echo "Service enabled for boot."
fi

# Now check if config is still incomplete (post-prompt, only apiEndpoint/PubNub matter for start)
if ! grep -q '"apiEndpoint":' "$CONFIG_PATH" 2>/dev/null || grep -q '"apiEndpoint": *""' "$CONFIG_PATH" 2>/dev/null; then
    echo "apiEndpoint incomplete; stopping service to avoid crashes."
    sudo systemctl stop noc-agent || true
else
    if sudo systemctl is-active --quiet noc-agent; then
        echo "Service is running; restarting to apply updates..."
        sudo systemctl restart noc-agent
    else
        echo "Service not running; starting now..."
        sudo systemctl start noc-agent
    fi
fi

# Verify service status
echo "Checking service status..."
sudo systemctl status noc-agent --no-pager -l

echo "Installation/Update complete! Source code is persistent in $INSTALL_SRC for future git pulls."
echo "The NOC Agent service is configured for auto-start and restart on failure (via systemd)."
echo "It subscribes to PubNub channels for AWS IoT-relayed commands from the control Lambda/UI and sends REST to Magewell Pro Convert NDI to HDMI decoders."
echo "To view logs (for debugging API downloads or device logins): sudo journalctl -u noc-agent -f"
echo "To stop/restart: sudo systemctl stop|restart noc-agent"
echo "For code updates: sudo $UPDATE_SCRIPT"