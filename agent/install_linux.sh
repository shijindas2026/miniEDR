#!/bin/bash

# MiniEDR Linux Agent Installer
# This script installs the miniedr-agent as a systemd service.

set -e

# Configuration
AGENT_NAME="miniedr-agent"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/miniedr"
LOG_DIR="/var/log/miniedr"
SERVICE_FILE="/etc/systemd/system/miniedr-agent.service"
BUILD_BINARY="./agent/exe/miniedr-agent"

# Check for root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (use sudo)"
  exit 1
fi

echo "Installing MiniEDR Agent..."

# 1. Configuration Check
if [ -z "$1" ]; then
    echo -n "Enter the EDR Server URL (e.g., http://your-server-ip:8000): "
    read SERVER_URL
else
    SERVER_URL=$1
fi

if [[ ! "$SERVER_URL" =~ ^http ]]; then
    echo "Error: Server URL must start with http:// or https://"
    exit 1
fi

# Create directories
echo "Creating data and log directories..."
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$DATA_DIR"
chmod 755 "$LOG_DIR"

# 2. Create config.json
echo "Creating configuration file at $DATA_DIR/config.json..."
cat > "$DATA_DIR/config.json" <<EOF
{
  "server": "$SERVER_URL"
}
EOF
chmod 644 "$DATA_DIR/config.json"

# 2. Check for binary
if [ ! -f "$BUILD_BINARY" ]; then
    echo "Error: Binary not found at $BUILD_BINARY. Please build it first using PyInstaller."
    exit 1
fi

# 3. Copy binary
echo "Copying binary to $INSTALL_DIR..."
cp "$BUILD_BINARY" "$INSTALL_DIR/$AGENT_NAME"
chmod 755 "$INSTALL_DIR/$AGENT_NAME"

# 4. Create Service File
echo "Creating systemd service..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Mini EDR Agent Service
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/$AGENT_NAME
Restart=always
RestartSec=10
WorkingDirectory=$DATA_DIR
StandardOutput=append:$LOG_DIR/agent_stdout.log
StandardError=append:$LOG_DIR/agent_stderr.log

[Install]
WantedBy=multi-user.target
EOF

# 5. Reload and Start
echo "Starting service..."
systemctl daemon-reload
systemctl enable miniedr-agent
systemctl restart miniedr-agent

echo "MiniEDR Agent installed and started successfully!"
echo "Status check: systemctl status miniedr-agent"
echo "Log file: $DATA_DIR/agent.log"
