#!/bin/bash

# dhyntoh Complete VPN Installation Script
# Installs prerequisites and main VPN in one command

set -e

echo "🚀 dhyntoh Complete VPN Installation"
echo "📦 This will install all prerequisites and the VPN"

# Download and run prerequisite script
echo "Step 1: Installing prerequisites..."
curl -sSL -o /tmp/prerequisite.sh https://raw.githubusercontent.com/dhyntoh/script/main/prerequisite.sh
chmod +x /tmp/prerequisite.sh
/tmp/prerequisite.sh

# Download and run main installer
echo "Step 2: Installing VPN..."
curl -sSL -o /tmp/install.sh https://raw.githubusercontent.com/dhyntoh/script/main/install.sh
chmod +x /tmp/install.sh
/tmp/install.sh

echo "🎉 Installation complete! Use 'dhyntoh-vpn status' to check services"
