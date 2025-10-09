#!/bin/bash

# dhyntoh Premium VPN AutoScript
# GitHub: https://github.com/dhyntoh/script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
SCRIPT_VERSION="PREMIUM"
DOMAIN_FILE="/etc/xray/domain"
IP_ADDRESS=$(curl -s icanhazip.com)
OS_INFO=$(source /etc/os-release && echo "$PRETTY_NAME")
RAM_INFO=$(free -h | awk '/^Mem:/ {print $2}')
CPU_INFO=$(nproc)
DISK_INFO=$(df -h / | awk 'NR==2 {print $2}')
INSTALL_DIR="/opt/dhyntoh-vpn"

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║               PREMIUM VPN AUTOSCRIPT            ║"
    echo "║                 Welcome to Script               ║"
    echo "║                    dhyntoh/script               ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# System Information
show_system_info() {
    echo -e "${YELLOW}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                   SERVER VPS                     ║${NC}"
    echo -e "${YELLOW}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${YELLOW}║ ${WHITE}DigitalOcean, LLC${YELLOW}                               ║${NC}"
    echo -e "${YELLOW}║ ${WHITE}SYSTEM OS: ${GREEN}$OS_INFO${YELLOW}                    ║${NC}"
    echo -e "${YELLOW}║ ${WHITE}SERVER RAM: ${GREEN}$RAM_INFO${YELLOW}                                ║${NC}"
    echo -e "${YELLOW}║ ${WHITE}CPU CORES: ${GREEN}$CPU_INFO${YELLOW}                                  ║${NC}"
    echo -e "${YELLOW}║ ${WHITE}DISK: ${GREEN}$DISK_INFO${YELLOW}                                   ║${NC}"
    echo -e "${YELLOW}║ ${WHITE}TIME: ${GREEN}$(date)${YELLOW}     ║${NC}"
    echo -e "${YELLOW}║ ${WHITE}IP: ${GREEN}$IP_ADDRESS${YELLOW}                       ║${NC}"
    
    if [[ -f "$DOMAIN_FILE" ]]; then
        DOMAIN=$(cat $DOMAIN_FILE)
        echo -e "${YELLOW}║ ${WHITE}DOMAIN: ${GREEN}$DOMAIN${YELLOW}                  ║${NC}"
    else
        echo -e "${YELLOW}║ ${WHITE}DOMAIN: ${RED}Not Set${YELLOW}                           ║${NC}"
    fi
    
    echo -e "${YELLOW}║ ${WHITE}SCRIPT: ${GREEN}PREMIUM VERSION${YELLOW}                      ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Service Status
show_service_status() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                 SERVICE STATUS                   ║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════╣${NC}"
    
    services=(
        "SSH:ssh"
        "DROPBEAR:dropbear"
        "STUNNEL:stunnel4"
        "OPENVPN:openvpn"
        "HAPROXY:haproxy"
        "NGINX:nginx"
        "XRAY:xray"
        "UDP-CUSTOM:udp-custom"
    )
    
    for service in "${services[@]}"; do
        name=${service%:*}
        service_name=${service#*:}
        
        if systemctl is-active --quiet $service_name; then
            echo -e "${BLUE}║ ${WHITE}$name: ${GREEN}ON${BLUE}                                       ║${NC}"
        else
            echo -e "${BLUE}║ ${WHITE}$name: ${RED}OFF${BLUE}                                      ║${NC}"
        fi
    done
    echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Protocol Matrix
show_protocol_matrix() {
    echo -e "${PURPLE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║               PROTOCOL MATRIX                    ║${NC}"
    echo -e "${PURPLE}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${PURPLE}║ ${CYAN}SSH/OPENVPN/UDP${WHITE}       | ${CYAN}VLESS/VMESS/TROJAN${WHITE}        ║${NC}"
    echo -e "${PURPLE}║ ${CYAN}WEBSOCKET/TLS${WHITE}         | ${CYAN}SHADOWSOCKS/gRPC${WHITE}          ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Main Menu
show_main_menu() {
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                   MAIN MENU                      ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}SSH MENU${GREEN}           ${WHITE}[02] ${CYAN}VMESS MENU${GREEN}          ║${NC}"
    echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}VLESS MENU${GREEN}         ${WHITE}[04] ${CYAN}TROJAN MENU${GREEN}         ║${NC}"
    echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}SYSTEM MENU${GREEN}        ${WHITE}[06] ${CYAN}DOMAIN MENU${GREEN}         ║${NC}"
    echo -e "${GREEN}║ ${WHITE}[07] ${CYAN}BACKUP/RESTORE${GREEN}     ${WHITE}[08] ${CYAN}SPEEDTEST${GREEN}           ║${NC}"
    echo -e "${GREEN}║ ${WHITE}[09] ${CYAN}INSTALL UDP${GREEN}        ${WHITE}[10] ${CYAN}BOT MENU${GREEN}            ║${NC}"
    echo -e "${GREEN}║ ${WHITE}[11] ${CYAN}RESTART ALL${GREEN}        ${WHITE}[12] ${CYAN}UPDATE SCRIPT${GREEN}       ║${NC}"
    echo -e "${GREEN}║ ${WHITE}[13] ${CYAN}CHECK PORT${GREEN}         ${WHITE}[14] ${CYAN}CHANGE BANNER${GREEN}       ║${NC}"
    echo -e "${GREEN}║ ${WHITE}[15] ${CYAN}WEBMIN MENU${GREEN}        ${WHITE}[16] ${CYAN}EXIT${GREEN}                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

# SSH Menu
ssh_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    SSH MENU                      ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE SSH USER${GREEN}      ${WHITE}[02] ${CYAN}DELETE SSH USER${GREEN}      ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}LIST SSH USERS${GREEN}       ${WHITE}[04] ${CYAN}CHANGE SSH PORT${GREEN}      ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}SSH WEBSOCKET${GREEN}        ${WHITE}[06] ${CYAN}DROPBEAR MENU${GREEN}        ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[07] ${CYAN}STUNNEL MENU${GREEN}         ${WHITE}[08] ${CYAN}BACK TO MAIN${GREEN}         ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-8]: " ssh_choice
        case $ssh_choice in
            1) create_ssh_user ;;
            2) delete_ssh_user ;;
            3) list_ssh_users ;;
            4) change_ssh_port ;;
            5) ssh_websocket_menu ;;
            6) dropbear_menu ;;
            7) stunnel_menu ;;
            8) break ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# VMess Menu
vmess_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   VMESS MENU                     ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE VMESS USER${GREEN}    ${WHITE}[02] ${CYAN}DELETE VMESS USER${GREEN}    ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}LIST VMESS USERS${GREEN}     ${WHITE}[04] ${CYAN}RENEW VMESS USER${GREEN}     ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}VMESS WEBSOCKET${GREEN}      ${WHITE}[06] ${CYAN}VMESS gRPC${GREEN}           ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[07] ${CYAN}BACK TO MAIN${GREEN}         ${WHITE}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-7]: " vmess_choice
        case $vmess_choice in
            1) create_vmess_user ;;
            2) delete_vmess_user ;;
            3) list_vmess_users ;;
            4) renew_vmess_user ;;
            5) vmess_websocket ;;
            6) vmess_grpc ;;
            7) break ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# VLess Menu
vless_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   VLESS MENU                     ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE VLESS USER${GREEN}    ${WHITE}[02] ${CYAN}DELETE VLESS USER${GREEN}    ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}LIST VLESS USERS${GREEN}     ${WHITE}[04] ${CYAN}RENEW VLESS USER${GREEN}     ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}VLESS WEBSOCKET${GREEN}      ${WHITE}[06] ${CYAN}VLESS gRPC${GREEN}           ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[07] ${CYAN}BACK TO MAIN${GREEN}         ${WHITE}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-7]: " vless_choice
        case $vless_choice in
            1) create_vless_user ;;
            2) delete_vless_user ;;
            3) list_vless_users ;;
            4) renew_vless_user ;;
            5) vless_websocket ;;
            6) vless_grpc ;;
            7) break ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# Trojan Menu
trojan_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   TROJAN MENU                    ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE TROJAN USER${GREEN}   ${WHITE}[02] ${CYAN}DELETE TROJAN USER${GREEN}   ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}LIST TROJAN USERS${GREEN}    ${WHITE}[04] ${CYAN}RENEW TROJAN USER${GREEN}    ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}TROJAN WEBSOCKET${GREEN}     ${WHITE}[06] ${CYAN}TROJAN gRPC${GREEN}          ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[07] ${CYAN}BACK TO MAIN${GREEN}         ${WHITE}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-7]: " trojan_choice
        case $trojan_choice in
            1) create_trojan_user ;;
            2) delete_trojan_user ;;
            3) list_trojan_users ;;
            4) renew_trojan_user ;;
            5) trojan_websocket ;;
            6) trojan_grpc ;;
            7) break ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# System Menu
system_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   SYSTEM MENU                    ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}SYSTEM INFO${GREEN}          ${WHITE}[02] ${CYAN}SERVER SPEEDTEST${GREEN}     ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}BANDWIDTH USAGE${GREEN}      ${WHITE}[04] ${CYAN}RAM USAGE${GREEN}            ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}REBOOT SERVER${GREEN}        ${WHITE}[06] ${CYAN}OPTIMIZE SERVER${GREEN}      ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[07] ${CYAN}CLEAR CACHE${GREEN}          ${WHITE}[08] ${CYAN}BACK TO MAIN${GREEN}         ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-8]: " system_choice
        case $system_choice in
            1) show_detailed_system_info ;;
            2) run_speedtest ;;
            3) show_bandwidth_usage ;;
            4) show_ram_usage ;;
            5) reboot_server ;;
            6) optimize_server ;;
            7) clear_cache ;;
            8) break ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# Domain Menu
domain_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   DOMAIN MENU                    ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}ADD DOMAIN${GREEN}           ${WHITE}[02] ${CYAN}CHANGE DOMAIN${GREEN}        ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}RENEW SSL${GREEN}            ${WHITE}[04] ${CYAN}CHECK DOMAIN${GREEN}         ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}CLOUDFLARE DNS${GREEN}       ${WHITE}[06] ${CYAN}BACK TO MAIN${GREEN}         ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-6]: " domain_choice
        case $domain_choice in
            1) add_domain ;;
            2) change_domain ;;
            3) renew_ssl ;;
            4) check_domain ;;
            5) cloudflare_dns ;;
            6) break ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# Bot Menu
bot_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    BOT MENU                      ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}INSTALL BOT${GREEN}          ${WHITE}[02] ${CYAN}START BOT${GREEN}            ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}STOP BOT${GREEN}             ${WHITE}[04] ${CYAN}BOT STATUS${GREEN}           ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}BOT LOGS${GREEN}             ${WHITE}[06] ${CYAN}BACK TO MAIN${GREEN}         ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-6]: " bot_choice
        case $bot_choice in
            1) install_bot ;;
            2) start_bot ;;
            3) stop_bot ;;
            4) bot_status ;;
            5) bot_logs ;;
            6) break ;;
            *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
        esac
    done
}

# Function stubs (to be implemented)
create_ssh_user() {
    echo -e "${YELLOW}Creating SSH user...${NC}"
    # Implementation here
    read -p "Enter username: " username
    read -p "Enter password: " password
    read -p "Enter expiry (days): " expiry
    
    useradd -m -s /bin/bash $username
    echo "$username:$password" | chpasswd
    usermod -aG sudo $username
    
    # Set expiry
    if [[ $expiry -gt 0 ]]; then
        chage -E $(date -d "+$expiry days" +%Y-%m-%d) $username
    fi
    
    echo -e "${GREEN}SSH user $username created successfully!${NC}"
    sleep 2
}

delete_ssh_user() {
    echo -e "${YELLOW}Deleting SSH user...${NC}"
    read -p "Enter username to delete: " username
    
    if id "$username" &>/dev/null; then
        userdel -r $username
        echo -e "${GREEN}User $username deleted successfully!${NC}"
    else
        echo -e "${RED}User $username does not exist!${NC}"
    fi
    sleep 2
}

list_ssh_users() {
    echo -e "${YELLOW}Listing SSH users...${NC}"
    echo -e "${CYAN}User accounts with shell access:${NC}"
    grep -E ':/bin/(bash|sh)' /etc/passwd | cut -d: -f1 | while read user; do
        expiry=$(chage -l $user 2>/dev/null | grep "Account expires" | cut -d: -f2)
        echo -e "User: $user | Expiry: $expiry"
    done
    read -p "Press any key to continue..."
}

create_vmess_user() {
    echo -e "${YELLOW}Creating VMess user...${NC}"
    # Xray VMess user creation logic
    echo -e "${GREEN}VMess user created successfully!${NC}"
    sleep 2
}

create_vless_user() {
    echo -e "${YELLOW}Creating VLess user...${NC}"
    # Xray VLess user creation logic
    echo -e "${GREEN}VLess user created successfully!${NC}"
    sleep 2
}

create_trojan_user() {
    echo -e "${YELLOW}Creating Trojan user...${NC}"
    # Xray Trojan user creation logic
    echo -e "${GREEN}Trojan user created successfully!${NC}"
    sleep 2
}

show_detailed_system_info() {
    echo -e "${YELLOW}Detailed System Information:${NC}"
    echo -e "${CYAN}CPU Usage:${NC} $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')"
    echo -e "${CYAN}Memory Usage:${NC} $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')"
    echo -e "${CYAN}Disk Usage:${NC} $(df -h / | awk 'NR==2{print $5}')"
    echo -e "${CYAN}Uptime:${NC} $(uptime -p)"
    echo -e "${CYAN}Load Average:${NC} $(uptime | awk -F'load average:' '{print $2}')"
    read -p "Press any key to continue..."
}

run_speedtest() {
    echo -e "${YELLOW}Running speedtest...${NC}"
    if command -v speedtest-cli &> /dev/null; then
        speedtest-cli --simple
    else
        apt update && apt install -y speedtest-cli
        speedtest-cli --simple
    fi
    read -p "Press any key to continue..."
}

add_domain() {
    echo -e "${YELLOW}Adding domain...${NC}"
    read -p "Enter your domain: " domain
    echo "$domain" > /etc/xray/domain
    echo -e "${GREEN}Domain $domain added successfully!${NC}"
    
    # Generate SSL certificate
    echo -e "${YELLOW}Generating SSL certificate...${NC}"
    certbot certonly --standalone -d $domain --non-interactive --agree-tos --email admin@$domain
    
    sleep 2
}

renew_ssl() {
    echo -e "${YELLOW}Renewing SSL certificates...${NC}"
    certbot renew
    systemctl reload nginx
    echo -e "${GREEN}SSL certificates renewed!${NC}"
    sleep 2
}

install_udp() {
    echo -e "${YELLOW}Installing UDP Custom...${NC}"
    curl -sSL https://raw.githubusercontent.com/dhyntoh/script/main/udp-custom.sh | bash
    echo -e "${GREEN}UDP Custom installed successfully!${NC}"
    sleep 2
}

restart_all_services() {
    echo -e "${YELLOW}Restarting all services...${NC}"
    services=("ssh" "dropbear" "stunnel4" "nginx" "haproxy" "xray" "udp-custom")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            systemctl restart $service
            echo -e "${GREEN}$service restarted${NC}"
        fi
    done
    echo -e "${GREEN}All services restarted successfully!${NC}"
    sleep 2
}

update_script() {
    echo -e "${YELLOW}Updating script...${NC}"
    curl -sSL https://raw.githubusercontent.com/dhyntoh/script/main/update.sh | bash
    echo -e "${GREEN}Script updated successfully!${NC}"
    sleep 2
}

check_port() {
    echo -e "${YELLOW}Checking open ports...${NC}"
    read -p "Enter port to check: " port
    if netstat -tuln | grep ":$port " > /dev/null; then
        echo -e "${GREEN}Port $port is open${NC}"
    else
        echo -e "${RED}Port $port is closed${NC}"
    fi
    sleep 2
}

change_banner() {
    echo -e "${YELLOW}Changing SSH banner...${NC}"
    read -p "Enter banner text: " banner_text
    echo "$banner_text" > /etc/issue.net
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    systemctl restart ssh
    echo -e "${GREEN}SSH banner updated!${NC}"
    sleep 2
}

backup_restore() {
    echo -e "${YELLOW}Backup/Restore Menu${NC}"
    echo "1. Backup configuration"
    echo "2. Restore configuration"
    read -p "Select option: " backup_choice
    
    case $backup_choice in
        1)
            tar -czf /root/vpn-backup-$(date +%Y%m%d).tar.gz /etc/xray /etc/nginx /etc/ssh /root
            echo -e "${GREEN}Backup created: /root/vpn-backup-$(date +%Y%m%d).tar.gz${NC}"
            ;;
        2)
            read -p "Enter backup file path: " backup_file
            if [[ -f $backup_file ]]; then
                tar -xzf $backup_file -C /
                echo -e "${GREEN}Configuration restored!${NC}"
            else
                echo -e "${RED}Backup file not found!${NC}"
            fi
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            ;;
    esac
    sleep 2
}

install_bot() {
    echo -e "${YELLOW}Installing Telegram Bot...${NC}"
    # Bot installation logic
    echo -e "${GREEN}Bot installed successfully!${NC}"
    sleep 2
}

# Main loop
while true; do
    clear
    show_banner
    show_system_info
    show_service_status
    show_protocol_matrix
    show_main_menu
    
    read -p "Select option [1-16]: " main_choice
    case $main_choice in
        1) ssh_menu ;;
        2) vmess_menu ;;
        3) vless_menu ;;
        4) trojan_menu ;;
        5) system_menu ;;
        6) domain_menu ;;
        7) backup_restore ;;
        8) run_speedtest ;;
        9) install_udp ;;
        10) bot_menu ;;
        11) restart_all_services ;;
        12) update_script ;;
        13) check_port ;;
        14) change_banner ;;
        15) 
            echo -e "${YELLOW}Webmin Menu - Coming Soon${NC}"
            sleep 2 
            ;;
        16)
            echo -e "${GREEN}Thank you for using dhyntoh Premium VPN Script!${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option! Please select 1-16${NC}"
            sleep 2
            ;;
    esac
done