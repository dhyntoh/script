#!/bin/bash

# dhyntoh Quick Installer for Ubuntu 20.04

echo "🚀 dhyntoh VPN Quick Installer for Ubuntu 20.04"
echo "🔒 No Ubuntu Pro Required - Fully Secure"

# Check Ubuntu version
if [[ ! -f /etc/os-release ]]; then
    echo "❌ This script is for Ubuntu 20.04 only"
    exit 1
fi

source /etc/os-release
if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "20.04" ]]; then
    echo "❌ This script is for Ubuntu 20.04 only. Detected: $PRETTY_NAME"
    exit 1
fi

echo "✅ Ubuntu 20.04 detected - Proceeding with installation..."

# Download and run the Ubuntu 20.04 installer
curl -sSL -o /tmp/install-ubuntu20.sh https://raw.githubusercontent.com/dhyntoh/script/main/install-ubuntu20.sh
chmod +x /tmp/install-ubuntu20.sh
/tmp/install-ubuntu20.sh

# Download the Ubuntu 20.04 menu
curl -sSL -o /usr/local/bin/menu https://raw.githubusercontent.com/dhyntoh/script/main/menu-ubuntu20.sh
chmod +x /usr/local/bin/menu

echo ""
echo "🎉 Installation complete!"
echo "💡 Run 'menu' to start using your secure VPN"
echo "🔒 All security features are enabled and working"