#!/bin/bash

# dhyntoh Premium VPN AutoScript Installer

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INSTALL]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
fi

# Check OS
if [[ ! -f /etc/os-release ]]; then
    error "Cannot determine OS"
fi

source /etc/os-release
OS=$ID

# Installation function
install_dependencies() {
    log "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt update && apt upgrade -y
            apt install -y curl wget git jq tar gzip build-essential \
                         net-tools iproute2 dnsutils socat bc python3 \
                         certbot haproxy nginx cron ufw stunnel4 dropbear \
                         screen netcat-openbsd speedtest-cli >> /dev/null 2>&1
            ;;
        centos)
            yum update -y
            yum install -y curl wget git jq tar gzip make gcc \
                         net-tools iproute bind-utils socat bc python3 \
                         certbot haproxy nginx crontabs firewalld \
                         stunnel dropbear >> /dev/null 2>&1
            ;;
    esac
    success "Dependencies installed"
}

install_xray() {
    log "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    success "Xray installed"
}

configure_firewall() {
    log "Configuring firewall..."
    
    case $OS in
        ubuntu|debian)
            ufw --force reset
            ufw allow ssh
            ufw allow 80
            ufw allow 443
            ufw allow 444
            ufw allow 445
            ufw allow 447
            ufw allow 777
            ufw allow 8443
            ufw allow 8880
            ufw --force enable
            ;;
        centos)
            systemctl start firewalld
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --permanent --add-port=80/tcp
            firewall-cmd --permanent --add-port=443/tcp
            firewall-cmd --permanent --add-port=444/tcp
            firewall-cmd --permanent --add-port=445/tcp
            firewall-cmd --permanent --add-port=447/tcp
            firewall-cmd --permanent --add-port=777/tcp
            firewall-cmd --permanent --add-port=8443/tcp
            firewall-cmd --permanent --add-port=8880/tcp
            firewall-cmd --reload
            ;;
    esac
    success "Firewall configured"
}

download_scripts() {
    log "Downloading scripts..."
    
    # Create directory
    mkdir -p /opt/dhyntoh-vpn
    
    # Download menu script
    curl -sSL -o /usr/local/bin/menu https://raw.githubusercontent.com/dhyntoh/script/main/menu.sh
    chmod +x /usr/local/bin/menu
    
    # Download other scripts
    scripts=("udp-custom.sh" "backup.sh" "bot-install.sh")
    for script in "${scripts[@]}"; do
        curl -sSL -o /opt/dhyntoh-vpn/$script https://raw.githubusercontent.com/dhyntoh/script/main/$script
        chmod +x /opt/dhyntoh-vpn/$script
    done
    
    success "Scripts downloaded"
}

setup_complete() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║           INSTALLATION COMPLETE!               ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║ Premium VPN AutoScript has been installed      ║"
    echo "║                                                  ║"
    echo "║ Usage:                                           ║"
    echo "║   - Run 'menu' to access the main menu          ║"
    echo "║   - All services are automatically configured   ║"
    echo "║   - Check /opt/dhyntoh-vpn for additional scripts║"
    echo "║                                                  ║"
    echo "║ Features:                                        ║"
    echo "║   ✓ SSH, Dropbear, Stunnel4                    ║"
    echo "║   ✓ VMess, VLess, Trojan, Shadowsocks          ║"
    echo "║   ✓ WebSocket & gRPC support                   ║"
    echo "║   ✓ UDP Custom                                 ║"
    echo "║   ✓ Telegram Bot                               ║"
    echo "║   ✓ Backup & Restore                           ║"
    echo "║   ✓ Speedtest & Monitoring                     ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Main installation
main() {
    clear
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║          dhyntoh Premium VPN Installer         ║"
    echo "║                 Version: PREMIUM               ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    install_dependencies
    install_xray
    configure_firewall
    download_scripts
    setup_complete
    
    echo -e "${YELLOW}"
    echo "Next steps:"
    echo "1. Run 'menu' to configure your VPN"
    echo "2. Add your domain using the Domain Menu"
    echo "3. Create users for different protocols"
    echo -e "${NC}"
}

main "$@"
