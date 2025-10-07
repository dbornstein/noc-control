#!/bin/bash

set -e  # Exit on any error

# Temporary directory for cloning
TEMP_DIR="/tmp/noc-agent-install"
CLONE_DIR="$TEMP_DIR/src"

echo "Starting NOC Agent installation..."

# Clone the repository (pull latest if exists)
if [ -d "$CLONE_DIR" ]; then
    echo "Repository already cloned, updating to latest..."
    cd "$CLONE_DIR"
    git pull origin main  # Assumes main branch; adjust if needed
else
    echo "Cloning repository from https://github.com/dbornstein/noc-control.git..."
    mkdir -p "$TEMP_DIR"
    git clone https://github.com/dbornstein/noc-control.git "$CLONE_DIR"
    cd "$CLONE_DIR"
fi

# Create system user if it doesn't exist 
if ! id -u noc-agent &>/dev/null; then
    echo "Creating system user 'noc-agent'..."
    sudo adduser --system --group --no-create-home noc-agent
else
    echo "System user 'noc-agent' already exists."
fi

# Create installation directory 
INSTALL_DIR="/opt/noc-agent"
sudo mkdir -p "$INSTALL_DIR"
sudo chown noc-agent:noc-agent "$INSTALL_DIR"

# Create virtual environment (recreate only if missing or corrupted)
VENV_DIR="$INSTALL_DIR/venv"
if [ ! -d "$VENV_DIR" ] || [ ! -f "$VENV_DIR/bin/python" ]; then
    echo "Creating/Recreating Python virtual environment in $VENV_DIR..."
    sudo rm -rf "$VENV_DIR"  # Clean slate if corrupted
    sudo -u noc-agent python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists and is valid."
fi

# Install/Upgrade the package editable into the venv ( always reinstall for updates)
echo "Installing/Updating noc-agent package..."
sudo -u noc-agent bash -c "
    source $VENV_DIR/bin/activate
    cd $CLONE_DIR
    pip install --upgrade pip
    pip install -e . --upgrade  # --upgrade ensures latest deps and code
"

# Copy/Overwrite configuration file (use template if no custom;overwrite for template case)
CONFIG_PATH="$INSTALL_DIR/agent_config.json"
if [ ! -f "$CONFIG_PATH" ] || [ ! -s "$CONFIG_PATH" ]; then  # If missing or empty
    echo "Copying agent configuration template to $CONFIG_PATH..."
    sudo cp "$CLONE_DIR/agent_config_template.json" "$CONFIG_PATH"
    sudo chown noc-agent:noc-agent "$CONFIG_PATH"
    echo "Note: Please customize $CONFIG_PATH with PubNub keys, AWS IoT topics, and Magewell TV controller IPs before starting the service."
elif grep -q '"pubnub_subscribe_key"' "$CONFIG_PATH" 2>/dev/null || ! grep -q '"pubnub_subscribe_key"' "$CONFIG_PATH" 2>/dev/null; then
    echo "Configuration exists but may need review for PubNub/AWS IoT setup."
fi

# Copy/Update systemd service (overwrite for latest version)
SERVICE_FILE="/etc/systemd/system/noc-agent.service"
echo "Setting up/Updating systemd service..."
sudo cp "$CLONE_DIR/noc-agent.service" "$SERVICE_FILE"
sudo chown root:root "$SERVICE_FILE"
sudo chmod 644 "$SERVICE_FILE"

# Reload systemd, enable, and restart service if running (to pick up updates)
echo "Configuring systemd service..."
sudo systemctl daemon-reload
if ! sudo systemctl is-enabled --quiet noc-agent; then
    sudo systemctl enable noc-agent
    echo "Service enabled for boot."
fi
if sudo systemctl is-active --quiet noc-agent; then
    echo "Service is running; restarting to apply updates..."
    sudo systemctl restart noc-agent
else
    echo "Service not running; starting now..."
    sudo systemctl start noc-agent
fi

# Verify service status
echo "Checking service status..."
sudo systemctl status noc-agent --no-pager -l

# Cleanup temporary clone (optional; comment out if you want to keep for debugging)
echo "Cleaning up temporary files..."
cd /
rm -rf "$TEMP_DIR"

echo "Installation/Update complete! The NOC Agent service is now running and will start automatically on boot."
echo "It handles PubNub subscriptions for AWS IoT commands and REST to Magewell decoders."
echo "To view logs: sudo journalctl -u noc-agent -f"
echo "To stop/restart: sudo systemctl stop|restart noc-agent"
echo "For HA: Run this script again with a modified service file (e.g., noc-agent-b.service) and config."