#!/bin/bash

# dhyntoh Complete Working VPN Menu
# ALL FEATURES WORKING: Create, Renew, Delete, List

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

# Banner
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║               COMPLETE VPN AUTOSCRIPT           ║"
    echo "║              ALL FEATURES WORKING               ║"
    echo "║                  dhyntoh/script                 ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Service Status
check_services() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                 SERVICE STATUS                   ║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════╣${NC}"
    
    services=("xray" "nginx" "haproxy" "stunnel4" "dropbear")
    all_running=true
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            echo -e "${BLUE}║ ${WHITE}$service: ${GREEN}✅ RUNNING${BLUE}                          ║${NC}"
        else
            echo -e "${BLUE}║ ${WHITE}$service: ${RED}❌ STOPPED${BLUE}                          ║${NC}"
            all_running=false
        fi
    done
    
    echo -e "${BLUE}╚══════════════════════════════════════════════════╝${NC}"
    
    if ! $all_running; then
        echo -e "${YELLOW}💡 Tip: Run 'vpn-manager fix-all' to start all services${NC}"
    fi
    echo ""
}

# VMess Menu - ALL FEATURES WORKING
vmess_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   VMESS MENU                     ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE VMESS USER${GREEN}    ${WHITE}[02] ${CYAN}RENEW VMESS USER${GREEN}     ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}DELETE VMESS USER${GREEN}    ${WHITE}[04] ${CYAN}LIST VMESS USERS${GREEN}     ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}BACK TO MAIN${GREEN}         ${WHITE}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-5]: " choice
        case $choice in
            1)
                echo -e "${YELLOW}Creating VMess User...${NC}"
                read -p "Enter username: " username
                read -p "Enter expiry (days): " expiry
                
                if [[ -n "$username" && -n "$expiry" ]]; then
                    vpn-user add vmess "$username" "$expiry"
                else
                    echo -e "${RED}Username and expiry are required!${NC}"
                fi
                ;;
            2)
                echo -e "${YELLOW}Renewing VMess User...${NC}"
                read -p "Enter username: " username
                read -p "Enter extra days: " days
                
                if [[ -n "$username" && -n "$days" ]]; then
                    vpn-user renew vmess "$username" "$days"
                else
                    echo -e "${RED}Username and days are required!${NC}"
                fi
                ;;
            3)
                echo -e "${YELLOW}Deleting VMess User...${NC}"
                read -p "Enter username to delete: " username
                
                if [[ -n "$username" ]]; then
                    vpn-user delete vmess "$username"
                else
                    echo -e "${RED}Username is required!${NC}"
                fi
                ;;
            4)
                echo -e "${YELLOW}Listing VMess Users...${NC}"
                vpn-user list vmess
                ;;
            5) break ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
        echo ""
        read -p "Press any key to continue..." -n1
        echo ""
    done
}

# VLess Menu - ALL FEATURES WORKING
vless_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   VLESS MENU                     ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE VLESS USER${GREEN}    ${WHITE}[02] ${CYAN}RENEW VLESS USER${GREEN}     ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}DELETE VLESS USER${GREEN}    ${WHITE}[04] ${CYAN}LIST VLESS USERS${GREEN}     ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}BACK TO MAIN${GREEN}         ${WHITE}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-5]: " choice
        case $choice in
            1)
                echo -e "${YELLOW}Creating VLess User...${NC}"
                read -p "Enter username: " username
                read -p "Enter expiry (days): " expiry
                
                if [[ -n "$username" && -n "$expiry" ]]; then
                    vpn-user add vless "$username" "$expiry"
                else
                    echo -e "${RED}Username and expiry are required!${NC}"
                fi
                ;;
            2)
                echo -e "${YELLOW}Renewing VLess User...${NC}"
                read -p "Enter username: " username
                read -p "Enter extra days: " days
                
                if [[ -n "$username" && -n "$days" ]]; then
                    vpn-user renew vless "$username" "$days"
                else
                    echo -e "${RED}Username and days are required!${NC}"
                fi
                ;;
            3)
                echo -e "${YELLOW}Deleting VLess User...${NC}"
                read -p "Enter username to delete: " username
                
                if [[ -n "$username" ]]; then
                    vpn-user delete vless "$username"
                else
                    echo -e "${RED}Username is required!${NC}"
                fi
                ;;
            4)
                echo -e "${YELLOW}Listing VLess Users...${NC}"
                vpn-user list vless
                ;;
            5) break ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
        echo ""
        read -p "Press any key to continue..." -n1
        echo ""
    done
}

# Trojan Menu - ALL FEATURES WORKING
trojan_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   TROJAN MENU                    ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE TROJAN USER${GREEN}   ${WHITE}[02] ${CYAN}RENEW TROJAN USER${GREEN}    ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}DELETE TROJAN USER${GREEN}   ${WHITE}[04] ${CYAN}LIST TROJAN USERS${GREEN}    ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}BACK TO MAIN${GREEN}         ${WHITE}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-5]: " choice
        case $choice in
            1)
                echo -e "${YELLOW}Creating Trojan User...${NC}"
                read -p "Enter username: " username
                read -p "Enter expiry (days): " expiry
                
                if [[ -n "$username" && -n "$expiry" ]]; then
                    vpn-user add trojan "$username" "$expiry"
                else
                    echo -e "${RED}Username and expiry are required!${NC}"
                fi
                ;;
            2)
                echo -e "${YELLOW}Renewing Trojan User...${NC}"
                read -p "Enter username: " username
                read -p "Enter extra days: " days
                
                if [[ -n "$username" && -n "$days" ]]; then
                    vpn-user renew trojan "$username" "$days"
                else
                    echo -e "${RED}Username and days are required!${NC}"
                fi
                ;;
            3)
                echo -e "${YELLOW}Deleting Trojan User...${NC}"
                read -p "Enter username to delete: " username
                
                if [[ -n "$username" ]]; then
                    vpn-user delete trojan "$username"
                else
                    echo -e "${RED}Username is required!${NC}"
                fi
                ;;
            4)
                echo -e "${YELLOW}Listing Trojan Users...${NC}"
                vpn-user list trojan
                ;;
            5) break ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
        echo ""
        read -p "Press any key to continue..." -n1
        echo ""
    done
}

# SSH Menu - ALL FEATURES WORKING
ssh_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                    SSH MENU                      ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}CREATE SSH USER${GREEN}      ${WHITE}[02] ${CYAN}RENEW SSH USER${GREEN}       ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}DELETE SSH USER${GREEN}      ${WHITE}[04] ${CYAN}LIST SSH USERS${GREEN}       ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}SERVICE STATUS${GREEN}       ${WHITE}[06] ${CYAN}BACK TO MAIN${GREEN}         ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-6]: " choice
        case $choice in
            1)
                echo -e "${YELLOW}Creating SSH User...${NC}"
                read -p "Enter username: " username
                read -p "Enter expiry (days): " expiry
                
                if [[ -n "$username" && -n "$expiry" ]]; then
                    vpn-user add ssh "$username" "$expiry"
                else
                    echo -e "${RED}Username and expiry are required!${NC}"
                fi
                ;;
            2)
                echo -e "${YELLOW}Renewing SSH User...${NC}"
                read -p "Enter username: " username
                read -p "Enter extra days: " days
                
                if [[ -n "$username" && -n "$days" ]]; then
                    vpn-user renew ssh "$username" "$days"
                else
                    echo -e "${RED}Username and days are required!${NC}"
                fi
                ;;
            3)
                echo -e "${YELLOW}Deleting SSH User...${NC}"
                read -p "Enter username to delete: " username
                
                if [[ -n "$username" ]]; then
                    vpn-user delete ssh "$username"
                else
                    echo -e "${RED}Username is required!${NC}"
                fi
                ;;
            4)
                echo -e "${YELLOW}Listing SSH Users...${NC}"
                vpn-user list ssh
                ;;
            5)
                echo -e "${YELLOW}SSH Service Status:${NC}"
                systemctl status dropbear --no-pager
                systemctl status stunnel4 --no-pager
                ;;
            6) break ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
        echo ""
        read -p "Press any key to continue..." -n1
        echo ""
    done
}

# System Menu - ALL FEATURES WORKING
system_menu() {
    while true; do
        clear
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   SYSTEM MENU                    ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}SERVICE STATUS${GREEN}       ${WHITE}[02] ${CYAN}RESTART ALL${GREEN}          ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}FIX SERVICES${GREEN}         ${WHITE}[04] ${CYAN}VIEW LOGS${GREEN}            ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}BACKUP CONFIG${GREEN}        ${WHITE}[06] ${CYAN}LIST ALL USERS${GREEN}       ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[07] ${CYAN}BACK TO MAIN${GREEN}         ${WHITE}                          ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        
        read -p "Select option [1-7]: " choice
        case $choice in
            1) vpn-manager status ;;
            2) 
                echo -e "${YELLOW}Restarting all services...${NC}"
                vpn-manager restart
                ;;
            3)
                echo -e "${YELLOW}Fixing all services...${NC}"
                vpn-manager fix-all
                ;;
            4)
                echo -e "${YELLOW}Showing Xray logs (Ctrl+C to exit)...${NC}"
                vpn-manager logs
                ;;
            5)
                echo -e "${YELLOW}Creating backup...${NC}"
                vpn-backup create
                ;;
            6)
                echo -e "${YELLOW}Listing all users...${NC}"
                vpn-user list all
                ;;
            7) break ;;
            *) echo -e "${RED}Invalid option!${NC}" ;;
        esac
        echo ""
        read -p "Press any key to continue..." -n1
        echo ""
    done
}

# Main Menu
main_menu() {
    while true; do
        clear
        show_banner
        check_services
        
        echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                   MAIN MENU                      ║${NC}"
        echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
        echo -e "${GREEN}║ ${WHITE}[01] ${CYAN}VMESS MENU${GREEN}           ${WHITE}[02] ${CYAN}VLESS MENU${GREEN}           ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[03] ${CYAN}TROJAN MENU${GREEN}          ${WHITE}[04] ${CYAN}SSH MENU${GREEN}             ║${NC}"
        echo -e "${GREEN}║ ${WHITE}[05] ${CYAN}SYSTEM MENU${GREEN}          ${WHITE}[06] ${CYAN}EXIT${GREEN}                 ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}🎯 ALL FEATURES WORKING: Create, Renew, Delete, List${NC}"
        echo ""
        
        read -p "Select option [1-6]: " choice
        case $choice in
            1) vmess_menu ;;
            2) vless_menu ;;
            3) trojan_menu ;;
            4) ssh_menu ;;
            5) system_menu ;;
            6) 
                echo -e "${GREEN}Thank you for using dhyntoh VPN!${NC}"
                exit 0
                ;;
            *) 
                echo -e "${RED}Invalid option!${NC}"
                sleep 1
                ;;
        esac
    done
}

# Check if installed
if [[ ! -f "/usr/local/bin/vpn-manager" ]]; then
    echo -e "${RED}VPN not installed. Run install.sh first${NC}"
    exit 1
fi

# Start main menu
main_menu
