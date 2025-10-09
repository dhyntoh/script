#!/bin/bash

# dhyntoh Script Updater

set -e

echo "🔄 Updating dhyntoh Premium Script..."

# Backup current config
tar -czf /root/backup-pre-update-$(date +%Y%m%d).tar.gz /etc/xray /etc/nginx /etc/haproxy 2>/dev/null || true

# Update scripts
curl -sSL -o /tmp/menu.sh https://raw.githubusercontent.com/dhyntoh/script/main/menu.sh
curl -sSL -o /tmp/install.sh https://raw.githubusercontent.com/dhyntoh/script/main/install.sh

# Replace if downloaded successfully
if [[ -f /tmp/menu.sh ]]; then
    mv /tmp/menu.sh /usr/local/bin/menu
    chmod +x /usr/local/bin/menu
fi

if [[ -f /tmp/install.sh ]]; then
    mv /tmp/install.sh /opt/dhyntoh-vpn/install.sh
    chmod +x /opt/dhyntoh-vpn/install.sh
fi

# Update Xray if needed
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

echo "✅ Update completed!"
echo "📦 Backup created: /root/backup-pre-update-$(date +%Y%m%d).tar.gz"