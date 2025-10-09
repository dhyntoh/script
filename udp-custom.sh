#!/bin/bash

# dhyntoh UDP Custom Installer

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Installing UDP Custom...${NC}"

# Install UDP Custom
cd /root
rm -rf udp
mkdir -p udp

# Download binary
wget -q -O /root/udp/udp-custom "https://github.com/dhyntoh/script/raw/main/udp-custom"
chmod +x /root/udp/udp-custom

# Create service
cat > /etc/systemd/system/udp-custom.service << EOF
[Unit]
Description=UDP Custom by dhyntoh
After=network.target

[Service]
User=root
Type=simple
ExecStart=/root/udp/udp-custom server
WorkingDirectory=/root/udp
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF

# Start service
systemctl daemon-reload
systemctl enable udp-custom
systemctl start udp-custom

echo -e "${GREEN}UDP Custom installed successfully!${NC}"
echo -e "${YELLOW}Status: $(systemctl is-active udp-custom)${NC}"