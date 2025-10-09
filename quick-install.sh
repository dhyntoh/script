#!/bin/bash

# dhyntoh Complete VPN Quick Installer

echo "🚀 dhyntoh Complete VPN Quick Installer"
echo "🎯 ALL FEATURES WORKING: Create, Renew, Delete, List"

# Download and run installer
curl -sSL -o /tmp/complete-install.sh https://raw.githubusercontent.com/dhyntoh/script/main/install.sh
chmod +x /tmp/complete-install.sh
/tmp/complete-install.sh

# Download menu
curl -sSL -o /usr/local/bin/menu https://raw.githubusercontent.com/dhyntoh/script/main/menu.sh
chmod +x /usr/local/bin/menu

echo "🎉 Complete installation finished!"
echo "💡 Run 'menu' to start using ALL features"
