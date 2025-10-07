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

# Copy/Overwrite configuration file (use template if no custom; idempotent overwrite for template case)
CONFIG_PATH="$INSTALL_DIR/agent_config.json"
if [ ! -f "$CONFIG_PATH" ] || [ ! -s "$CONFIG_PATH" ]; then  # If missing or empty
    echo "Copying agent configuration template to $CONFIG_PATH..."
    sudo cp "$INSTALL_SRC/agent_config_template.json" "$CONFIG_PATH"
fi
sudo chown noc-agent:noc-agent "$CONFIG_PATH"  # Ensure ownership

# Enhanced config validation (warn if incomplete)
if ! grep -q '"agentId":' "$CONFIG_PATH" 2>/dev/null || grep -q '"agentId": *"noc-agent-xxx"' "$CONFIG_PATH" 2>/dev/null; then
    echo "WARNING: agent_config.json appears incomplete (missing or placeholder agentId). Edit it with your AWS API endpoint, API key, and agentId before restarting the service."
    echo "Example: sudo vi $CONFIG_PATH"
fi
if ! grep -q '"apiEndpoint":' "$CONFIG_PATH" 2>/dev/null || grep -q '"apiEndpoint": *""' "$CONFIG_PATH" 2>/dev/null; then
    echo "WARNING: apiEndpoint missing or empty in $CONFIG_PATH. Required for downloading config from AWS (MongoDB/TAG integration)."
fi
if ! grep -q '"pubnubConfig"' "$CONFIG_PATH" 2>/dev/null || ! grep -q '"subscribeKey"' "$CONFIG_PATH" 2>/dev/null; then
    echo "WARNING: PubNub config (subscribeKey, etc.) missing in $CONFIG_PATH or downloaded agent config. Needed for AWS IoT command relay."
fi

# Copy/Update systemd service (idempotent: overwrite for latest version)
SERVICE_FILE="/etc/systemd/system/noc-agent.service"
echo "Setting up/Updating systemd service..."
sudo cp "$INSTALL_SRC/noc-agent.service" "$SERVICE_FILE"
sudo chown root:root "$SERVICE_FILE"
sudo chmod 644 "$SERVICE_FILE"

# Ensure ExecStart uses the console script (noc-agent) with --agent and --config-file flags
# This fixes the ModuleNotFoundError by avoiding -m noc_agent.main
echo "Configuring ExecStart for console script invocation..."
sudo bash -c "
    sed -i 's|ExecStart=.*|ExecStart=$VENV_DIR/bin/noc-agent --agent --config-file $CONFIG_PATH|g' '$SERVICE_FILE'
"

# Reload systemd, enable (idempotent), and manage service
echo "Configuring systemd service..."
sudo systemctl daemon-reload
if ! sudo systemctl is-enabled --quiet noc-agent; then
    sudo systemctl enable noc-agent
    echo "Service enabled for boot."
fi

# If config is incomplete, stop/don't start; else manage as before
if grep -q '"agentId": *"noc-agent-xxx"' "$CONFIG_PATH" 2>/dev/null || ! grep -q '"apiEndpoint":' "$CONFIG_PATH" 2>/dev/null; then
    echo "Config incomplete; stopping service to avoid crashes."
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
echo "For HA: Duplicate setup (e.g., /opt/noc-agent-b) with unique agentId/config and service file."
echo "Next: Customize $CONFIG_PATH (agentId, apiEndpoint for MongoDB/TAG sync, PubNub keys) and restart."