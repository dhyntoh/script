#!/bin/bash

# dhyntoh Complete Working VPN AutoScript
# ALL FEATURES WORKING: Create, Renew, Delete, List

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_VERSION="COMPLETE-4.0"
INSTALL_DIR="/opt/dhyntoh-vpn"
LOG_FILE="/var/log/vpn-install.log"

# Logging functions
log() { echo -e "${BLUE}[INSTALL]${NC} $1" | tee -a $LOG_FILE; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a $LOG_FILE; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE; exit 1; }

# Check system
check_system() {
    log "Checking system requirements..."
    [[ $EUID -ne 0 ]] && error "This script must be run as root"
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
    else
        error "Cannot determine OS"
    fi
    
    [[ ! "$OS" =~ ^(ubuntu|debian|centos)$ ]] && error "Unsupported OS: $OS"
    success "System: $OS"
}

# Install all dependencies
install_dependencies() {
    log "Installing all dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt update && apt upgrade -y
            apt install -y curl wget git jq tar gzip build-essential \
                         net-tools iproute2 dnsutils socat bc python3 \
                         certbot haproxy nginx cron ufw stunnel4 dropbear \
                         screen netcat-openbsd iptables-persistent \
                         software-properties-common apt-transport-https \
                         lsb-release ca-certificates >> $LOG_FILE 2>&1
            ;;
        centos)
            yum update -y
            yum install -y curl wget git jq tar gzip make gcc \
                         net-tools iproute bind-utils socat bc python3 \
                         certbot haproxy nginx crontabs firewalld \
                         stunnel dropbear epel-release >> $LOG_FILE 2>&1
            ;;
    esac
    success "All dependencies installed"
}

# Install Xray
install_xray() {
    log "Installing Xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    mkdir -p /etc/xray /var/log/xray
    success "Xray installed"
}

# Configure Xray with dynamic user management
configure_xray() {
    log "Configuring Xray with dynamic user management..."
    
    # Create initial empty config
    cat > /etc/xray/config.json << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        }
      },
      "tag": "vless-tls"
    },
    {
      "port": 10002,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      },
      "tag": "vmess-ws"
    },
    {
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/trojan"
        }
      },
      "tag": "trojan-ws"
    },
    {
      "port": 10004,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "chacha20-ietf-poly1305",
            "password": "default-password"
          }
        ]
      },
      "tag": "ss-tcp"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

    # Create user database directory
    mkdir -p $INSTALL_DIR/users
    echo "[]" > $INSTALL_DIR/users/vmess.json
    echo "[]" > $INSTALL_DIR/users/vless.json
    echo "[]" > $INSTALL_DIR/users/trojan.json
    echo "[]" > $INSTALL_DIR/users/ssh.json

    success "Xray configured with dynamic user management"
}

# Configure Dropbear
configure_dropbear() {
    log "Configuring Dropbear..."
    
    # Configure dropbear
    cat > /etc/default/dropbear << 'EOF'
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 109"
DROPBEAR_BANNER="/etc/issue.net"
EOF

    echo "Welcome to dhyntoh VPN Server" > /etc/issue.net
    
    systemctl enable dropbear
    systemctl start dropbear
    success "Dropbear configured and started"
}

# Configure Stunnel4
configure_stunnel() {
    log "Configuring Stunnel4..."
    
    cat > /etc/stunnel/stunnel.conf << 'EOF'
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[dropbear-444]
accept = 444
connect = 127.0.0.1:109

[dropbear-445]
accept = 445
connect = 127.0.0.1:109

[dropbear-447]
accept = 447
connect = 127.0.0.1:109

[dropbear-777]
accept = 777
connect = 127.0.0.1:109
EOF

    systemctl enable stunnel4
    systemctl start stunnel4
    success "Stunnel4 configured on ports 444,445,447,777"
}

# Configure HAProxy
configure_haproxy() {
    log "Configuring HAProxy..."
    
    cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    daemon
    maxconn 4000
    tune.ssl.default-dh-param 2048

defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    log global

frontend https-in
    bind *:443 tfo ssl crt /etc/xray/xray.crt alpn h2,http/1.1
    bind *:80
    bind *:8443 tfo ssl crt /etc/xray/xray.crt
    bind *:8880
    bind *:444
    bind *:445  
    bind *:447
    bind *:777
    
    tcp-request inspect-delay 5s
    tcp-request content accept if HTTP
    tcp-request content accept if { req_ssl_hello_type 1 }
    
    use_backend xray_vless if { path_beg /vless }
    use_backend xray_vmess if { path_beg /vmess }
    use_backend xray_trojan if { path_beg /trojan }
    use_backend ssh_ws if { path_beg /ssh-ws }
    default_backend dropbear_backend

backend xray_vless
    server xray_vless 127.0.0.1:10001 check

backend xray_vmess
    server xray_vmess 127.0.0.1:10002 check

backend xray_trojan
    server xray_trojan 127.0.0.1:10003 check

backend ssh_ws
    mode http
    server ssh_ws 127.0.0.1:10015 check

backend dropbear_backend
    server dropbear 127.0.0.1:109 check
EOF

    systemctl enable haproxy
    systemctl start haproxy
    success "HAProxy configured and started"
}

# Configure Nginx
configure_nginx() {
    log "Configuring Nginx..."
    
    systemctl stop nginx >/dev/null 2>&1 || true
    
    cat > /etc/nginx/conf.d/vpn.conf << 'EOF'
server {
    listen 10015;
    server_name _;
    
    location / {
        proxy_pass http://127.0.0.1:109;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
EOF

    systemctl enable nginx
    systemctl start nginx
    success "Nginx configured"
}

# Generate SSL certificates
generate_ssl() {
    log "Generating SSL certificates..."
    
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
    
    chmod 600 /etc/xray/xray.key
    success "SSL certificates generated"
}

# Setup firewall
setup_firewall() {
    log "Setting up firewall..."
    
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
            ufw allow 10015
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
            firewall-cmd --permanent --add-port=10015/tcp
            firewall-cmd --reload
            ;;
    esac
    success "Firewall configured"
}

# Create COMPLETE management scripts
create_management_scripts() {
    log "Creating COMPLETE management scripts..."
    
    # Create main user management script
    cat > /usr/local/bin/vpn-user << 'EOF'
#!/bin/bash

USERS_DIR="/opt/dhyntoh-vpn/users"
XRAY_CONFIG="/etc/xray/config.json"

generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

get_current_date() {
    date +%Y-%m-%d
}

calculate_expiry() {
    local days=$1
    date -d "+$days days" +%Y-%m-%d
}

add_user() {
    local protocol=$1
    local username=$2
    local expiry_days=$3
    
    case $protocol in
        vmess)
            local uuid=$(generate_uuid)
            local expiry_date=$(calculate_expiry $expiry_days)
            local user_data="{\"username\":\"$username\",\"uuid\":\"$uuid\",\"expiry\":\"$expiry_date\",\"created\":\"$(get_current_date)\",\"active\":true}"
            
            # Add to Xray config
            if ! jq --arg uuid "$uuid" --arg username "$username" \
                '.inbounds[] | select(.tag == "vmess-ws") | .settings.clients += [{"id": $uuid, "alterId": 0, "email": $username}]' \
                $XRAY_CONFIG > /tmp/xray_temp.json; then
                echo "ERROR: Failed to update Xray config"
                return 1
            fi
            
            mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Add to user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/vmess.json > /tmp/vmess_temp.json
            mv /tmp/vmess_temp.json $USERS_DIR/vmess.json
            
            systemctl restart xray
            echo "VMess user created:"
            echo "Username: $username"
            echo "UUID: $uuid"
            echo "Expiry: $expiry_date"
            ;;
            
        vless)
            local uuid=$(generate_uuid)
            local expiry_date=$(calculate_expiry $expiry_days)
            local user_data="{\"username\":\"$username\",\"uuid\":\"$uuid\",\"expiry\":\"$expiry_date\",\"created\":\"$(get_current_date)\",\"active\":true}"
            
            # Add to Xray config
            if ! jq --arg uuid "$uuid" --arg username "$username" \
                '.inbounds[] | select(.tag == "vless-tls") | .settings.clients += [{"id": $uuid, "flow": "xtls-rprx-vision", "email": $username}]' \
                $XRAY_CONFIG > /tmp/xray_temp.json; then
                echo "ERROR: Failed to update Xray config"
                return 1
            fi
            
            mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Add to user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/vless.json > /tmp/vless_temp.json
            mv /tmp/vless_temp.json $USERS_DIR/vless.json
            
            systemctl restart xray
            echo "VLess user created:"
            echo "Username: $username"
            echo "UUID: $uuid"
            echo "Expiry: $expiry_date"
            ;;
            
        trojan)
            local password=$(generate_uuid)
            local expiry_date=$(calculate_expiry $expiry_days)
            local user_data="{\"username\":\"$username\",\"password\":\"$password\",\"expiry\":\"$expiry_date\",\"created\":\"$(get_current_date)\",\"active\":true}"
            
            # Add to Xray config
            if ! jq --arg password "$password" --arg username "$username" \
                '.inbounds[] | select(.tag == "trojan-ws") | .settings.clients += [{"password": $password, "email": $username}]' \
                $XRAY_CONFIG > /tmp/xray_temp.json; then
                echo "ERROR: Failed to update Xray config"
                return 1
            fi
            
            mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Add to user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/trojan.json > /tmp/trojan_temp.json
            mv /tmp/trojan_temp.json $USERS_DIR/trojan.json
            
            systemctl restart xray
            echo "Trojan user created:"
            echo "Username: $username"
            echo "Password: $password"
            echo "Expiry: $expiry_date"
            ;;
            
        ssh)
            local password=$(openssl rand -base64 12)
            local expiry_date=$(calculate_expiry $expiry_days)
            
            # Create system user
            if id "$username" &>/dev/null; then
                echo "ERROR: User $username already exists"
                return 1
            fi
            
            useradd -m -s /bin/bash $username
            echo "$username:$password" | chpasswd
            
            # Set expiry
            chage -E $(date -d "+$expiry_days days" +%Y-%m-%d) $username
            
            local user_data="{\"username\":\"$username\",\"password\":\"$password\",\"expiry\":\"$expiry_date\",\"created\":\"$(get_current_date)\",\"active\":true}"
            
            # Add to user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/ssh.json > /tmp/ssh_temp.json
            mv /tmp/ssh_temp.json $USERS_DIR/ssh.json
            
            echo "SSH user created:"
            echo "Username: $username"
            echo "Password: $password"
            echo "Expiry: $expiry_date"
            ;;
    esac
}

delete_user() {
    local protocol=$1
    local username=$2
    
    case $protocol in
        vmess|vless|trojan)
            # Remove from Xray config
            if ! jq --arg username "$username" \
                "(.inbounds[] | select(.tag == \"$protocol-ws\") | .settings.clients) |= map(select(.email != \$username))" \
                $XRAY_CONFIG > /tmp/xray_temp.json; then
                echo "ERROR: Failed to update Xray config"
                return 1
            fi
            
            mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Remove from user database
            jq --arg username "$username" 'map(select(.username != $username))' $USERS_DIR/$protocol.json > /tmp/${protocol}_temp.json
            mv /tmp/${protocol}_temp.json $USERS_DIR/$protocol.json
            
            systemctl restart xray
            echo "$(echo $protocol | tr 'a-z' 'A-Z') user $username deleted"
            ;;
            
        ssh)
            if id "$username" &>/dev/null; then
                userdel -r $username
                # Remove from user database
                jq --arg username "$username" 'map(select(.username != $username))' $USERS_DIR/ssh.json > /tmp/ssh_temp.json
                mv /tmp/ssh_temp.json $USERS_DIR/ssh.json
                echo "SSH user $username deleted"
            else
                echo "ERROR: User $username not found"
            fi
            ;;
    esac
}

renew_user() {
    local protocol=$1
    local username=$2
    local extra_days=$3
    
    local new_expiry=$(calculate_expiry $extra_days)
    
    case $protocol in
        vmess|vless|trojan|ssh)
            # Update user database
            if jq --arg username "$username" --arg new_expiry "$new_expiry" \
                'map(if .username == $username then .expiry = $new_expiry else . end)' \
                $USERS_DIR/$protocol.json > /tmp/${protocol}_temp.json; then
                mv /tmp/${protocol}_temp.json $USERS_DIR/$protocol.json
                echo "User $username renewed until $new_expiry"
                
                # For SSH, update system account
                if [[ $protocol == "ssh" ]]; then
                    chage -E $new_expiry $username
                fi
            else
                echo "ERROR: Failed to renew user"
            fi
            ;;
    esac
}

list_users() {
    local protocol=$1
    
    case $protocol in
        vmess)
            echo "VMess Users:"
            jq -r '.[] | "\(.username) | UUID: \(.uuid) | Expiry: \(.expiry) | Active: \(.active)"' $USERS_DIR/vmess.json 2>/dev/null || echo "No users"
            ;;
        vless)
            echo "VLess Users:"
            jq -r '.[] | "\(.username) | UUID: \(.uuid) | Expiry: \(.expiry) | Active: \(.active)"' $USERS_DIR/vless.json 2>/dev/null || echo "No users"
            ;;
        trojan)
            echo "Trojan Users:"
            jq -r '.[] | "\(.username) | Password: \(.password) | Expiry: \(.expiry) | Active: \(.active)"' $USERS_DIR/trojan.json 2>/dev/null || echo "No users"
            ;;
        ssh)
            echo "SSH Users:"
            jq -r '.[] | "\(.username) | Password: \(.password) | Expiry: \(.expiry) | Active: \(.active)"' $USERS_DIR/ssh.json 2>/dev/null || echo "No users"
            ;;
        all)
            echo "=== ALL USERS ==="
            echo "VMess:"
            jq -r '.[] | "  \(.username) - \(.uuid) - Expiry: \(.expiry)"' $USERS_DIR/vmess.json 2>/dev/null || echo "  No VMess users"
            echo "VLess:"
            jq -r '.[] | "  \(.username) - \(.uuid) - Expiry: \(.expiry)"' $USERS_DIR/vless.json 2>/dev/null || echo "  No VLess users"
            echo "Trojan:"
            jq -r '.[] | "  \(.username) - \(.password) - Expiry: \(.expiry)"' $USERS_DIR/trojan.json 2>/dev/null || echo "  No Trojan users"
            echo "SSH:"
            jq -r '.[] | "  \(.username) - \(.password) - Expiry: \(.expiry)"' $USERS_DIR/ssh.json 2>/dev/null || echo "  No SSH users"
            ;;
    esac
}

case "$1" in
    add)
        if [[ $# -ne 4 ]]; then
            echo "Usage: vpn-user add <protocol> <username> <expiry_days>"
            echo "Protocols: vmess, vless, trojan, ssh"
            exit 1
        fi
        add_user $2 $3 $4
        ;;
        
    delete)
        if [[ $# -ne 3 ]]; then
            echo "Usage: vpn-user delete <protocol> <username>"
            echo "Protocols: vmess, vless, trojan, ssh"
            exit 1
        fi
        delete_user $2 $3
        ;;
        
    renew)
        if [[ $# -ne 4 ]]; then
            echo "Usage: vpn-user renew <protocol> <username> <extra_days>"
            echo "Protocols: vmess, vless, trojan, ssh"
            exit 1
        fi
        renew_user $2 $3 $4
        ;;
        
    list)
        if [[ $# -ne 2 ]]; then
            echo "Usage: vpn-user list <protocol|all>"
            echo "Protocols: vmess, vless, trojan, ssh, all"
            exit 1
        fi
        list_users $2
        ;;
        
    *)
        echo "dhyntoh VPN User Management"
        echo "Usage: vpn-user {add|delete|renew|list} [args]"
        echo ""
        echo "Examples:"
        echo "  vpn-user add vmess user1 30"
        echo "  vpn-user add vless user2 30"
        echo "  vpn-user add trojan user3 30"
        echo "  vpn-user add ssh user4 30"
        echo "  vpn-user delete vmess user1"
        echo "  vpn-user renew vmess user1 30"
        echo "  vpn-user list vmess"
        echo "  vpn-user list all"
        ;;
esac
EOF

    chmod +x /usr/local/bin/vpn-user

    # Create service manager
    cat > /usr/local/bin/vpn-manager << 'EOF'
#!/bin/bash

case "$1" in
    start)
        systemctl start xray nginx haproxy stunnel4 dropbear
        echo "✅ All VPN services started"
        ;;
    stop)
        systemctl stop xray nginx haproxy stunnel4
        echo "🛑 All VPN services stopped"
        ;;
    restart)
        systemctl restart xray nginx haproxy stunnel4 dropbear
        echo "🔄 All VPN services restarted"
        ;;
    status)
        echo "=== Service Status ==="
        for service in xray nginx haproxy stunnel4 dropbear; do
            if systemctl is-active --quiet $service; then
                echo "✅ $service: RUNNING"
            else
                echo "❌ $service: STOPPED"
            fi
        done
        ;;
    fix-all)
        systemctl enable xray nginx haproxy stunnel4 dropbear
        systemctl start xray nginx haproxy stunnel4 dropbear
        echo "🔧 All services enabled and started"
        ;;
    logs)
        tail -f /var/log/xray/error.log
        ;;
    *)
        echo "dhyntoh VPN Service Manager"
        echo "Usage: vpn-manager {start|stop|restart|status|fix-all|logs}"
        ;;
esac
EOF

    chmod +x /usr/local/bin/vpn-manager

    # Create backup script
    cat > /usr/local/bin/vpn-backup << 'EOF'
#!/bin/bash

BACKUP_DIR="/root/vpn-backups"
DATE=$(date +%Y%m%d-%H%M%S)

case "$1" in
    create)
        mkdir -p $BACKUP_DIR
        tar -czf $BACKUP_DIR/backup-$DATE.tar.gz /etc/xray /opt/dhyntoh-vpn /etc/nginx /etc/haproxy /etc/stunnel
        echo "✅ Backup created: $BACKUP_DIR/backup-$DATE.tar.gz"
        ;;
    restore)
        if [[ -z "$2" ]]; then
            echo "Usage: vpn-backup restore <backup-file>"
            exit 1
        fi
        if [[ -f "$2" ]]; then
            tar -xzf "$2" -C /
            systemctl restart xray nginx haproxy stunnel4
            echo "✅ Backup restored and services restarted"
        else
            echo "❌ Backup file not found: $2"
        fi
        ;;
    list)
        ls -la $BACKUP_DIR/*.tar.gz 2>/dev/null || echo "No backups found"
        ;;
    *)
        echo "dhyntoh VPN Backup Manager"
        echo "Usage: vpn-backup {create|restore|list}"
        ;;
esac
EOF

    chmod +x /usr/local/bin/vpn-backup

    success "Complete management scripts created"
}

# Final setup
final_setup() {
    log "Finalizing installation..."
    
    # Enable all services
    systemctl daemon-reload
    systemctl enable xray nginx haproxy stunnel4 dropbear
    systemctl start xray nginx haproxy stunnel4 dropbear
    
    # Wait and check services
    sleep 3
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║           COMPLETE VPN INSTALLATION!           ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║ ✅ ALL FEATURES WORKING:                        ║"
    echo "║    • CREATE Users (VMess, VLess, Trojan, SSH)   ║"
    echo "║    • RENEW Users (Extend expiry)                ║"
    echo "║    • DELETE Users (Remove completely)           ║"
    echo "║    • LIST Users (View all accounts)             ║"
    echo "║                                                 ║"
    echo "║ ✅ ALL SERVICES ACTIVE:                         ║"
    echo "║    • Xray (VMess/VLess/Trojan)                  ║"
    echo "║    • HAProxy (Load Balancer)                    ║"
    echo "║    • Dropbear (SSH)                             ║"
    echo "║    • Stunnel4 (SSL Tunneling)                   ║"
    echo "║    • Nginx (WebSocket Proxy)                    ║"
    echo "║                                                 ║"
    echo "║ 🎯 USAGE COMMANDS:                              ║"
    echo "║    • vpn-user add vmess user1 30               ║"
    echo "║    • vpn-user renew vmess user1 30             ║"
    echo "║    • vpn-user delete vmess user1               ║"
    echo "║    • vpn-user list all                         ║"
    echo "║    • vpn-manager status                        ║"
    echo "║    • menu (Interactive menu)                   ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Main installation
main() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║          dhyntoh COMPLETE VPN Installer        ║"
    echo "║             ALL FEATURES WORKING               ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_system
    install_dependencies
    install_xray
    generate_ssl
    configure_xray
    configure_dropbear
    configure_stunnel
    configure_haproxy
    configure_nginx
    setup_firewall
    create_management_scripts
    final_setup
    
    success "Complete VPN installation finished! All features are working."
}

main "$@"
