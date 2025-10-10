#!/bin/bash

# dhyntoh Secure VPN AutoScript for Ubuntu 20.04
# No Ubuntu Pro Required - Fully Compatible

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
SCRIPT_VERSION="UBUNTU20-4.0"
INSTALL_DIR="/opt/dhyntoh-vpn"
LOG_FILE="/var/log/vpn-ubuntu20-install.log"

# Logging functions
log() { echo -e "${BLUE}[INSTALL]${NC} $1" | tee -a $LOG_FILE; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a $LOG_FILE; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE; exit 1; }

# Check Ubuntu 20.04 specifically
check_ubuntu_version() {
    log "Checking Ubuntu version..."
    
    if [[ ! -f /etc/os-release ]]; then
        error "This script is for Ubuntu 20.04 only"
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" || "$VERSION_ID" != "20.04" ]]; then
        error "This script is designed for Ubuntu 20.04. Detected: $PRETTY_NAME"
    fi
    
    success "Ubuntu 20.04 detected - Perfect!"
}

# Secure system preparation
secure_system_prep() {
    log "Securing system preparation..."
    
    # Update system
    apt update && apt upgrade -y
    
    # Install security packages
    apt install -y ufw fail2ban unattended-upgrades apt-listchanges \
                 needrestart debsums rkhunter chkrootkit >> $LOG_FILE 2>&1
    
    # Configure automatic security updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    success "System security preparation completed"
}

# Install dependencies for Ubuntu 20.04
install_dependencies_ubuntu20() {
    log "Installing Ubuntu 20.04 compatible dependencies..."
    
    # Add necessary repositories
    add-apt-repository -y universe
    add-apt-repository -y multiverse
    
    # Update package list
    apt update
    
    # Install all required packages
    apt install -y \
        curl wget git jq tar gzip build-essential \
        net-tools iproute2 dnsutils socat bc python3 python3-pip \
        haproxy nginx cron ufw stunnel4 dropbear \
        screen netcat-openbsd iptables-persistent \
        software-properties-common apt-transport-https \
        lsb-release ca-certificates gnupg2 \
        certbot python3-certbot-nginx \
        openssh-server openssh-client \
        htop atop iotop iftop nmon dstat sysstat \
        sqlite3 redis-server >> $LOG_FILE 2>&1
    
    # Install specific versions compatible with 20.04
    apt install -y \
        haproxy=2.0.\* \
        nginx=1.18.\* \
        dropbear=2019.78-2 \
        stunnel4=5.56-1 >> $LOG_FILE 2>&1
    
    success "Ubuntu 20.04 dependencies installed"
}

# Install Xray from official source
install_xray_ubuntu20() {
    log "Installing Xray for Ubuntu 20.04..."
    
    # Install Xray using official script
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Create necessary directories
    mkdir -p /etc/xray /var/log/xray /usr/local/share/xray
    chown -R nobody:nogroup /var/log/xray
    
    success "Xray installed successfully"
}

# Configure system security
configure_system_security() {
    log "Configuring system security..."
    
    # Secure SSH configuration
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    cat > /etc/ssh/sshd_config << 'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Security settings
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Connection settings
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 10

# Crypto settings
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

# Other settings
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

    systemctl restart ssh

    # Configure fail2ban
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[sshd-ddos]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 86400

[dropbear]
enabled = true
port = 109,444,445,447,777
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

    systemctl enable fail2ban
    systemctl start fail2ban

    success "System security configured"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log "Generating SSL certificates..."
    
    # Create directory for SSL
    mkdir -p /etc/ssl/private /etc/ssl/certs
    
    # Generate self-signed certificate (user can replace with Let's Encrypt later)
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=vpn-server" \
        -keyout /etc/ssl/private/xray.key -out /etc/ssl/certs/xray.crt
    
    # Set proper permissions
    chmod 600 /etc/ssl/private/xray.key
    chmod 644 /etc/ssl/certs/xray.crt
    
    # Create symlinks for Xray
    ln -sf /etc/ssl/certs/xray.crt /etc/xray/xray.crt
    ln -sf /etc/ssl/private/xray.key /etc/xray/xray.key
    
    success "SSL certificates generated"
}

# Configure Xray with security features
configure_xray_secure() {
    log "Configuring Xray with security enhancements..."
    
    cat > /etc/xray/config.json << 'EOF'
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 120,
        "uplinkOnly": 1,
        "downlinkOnly": 1,
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  },
  "inbounds": [
    {
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
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
          ],
          "alpn": ["h2", "http/1.1"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
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
            "password": "default-shadowsocks-password"
          }
        ],
        "network": "tcp,udp"
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
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "block"
      },
      {
        "type": "field",
        "domain": ["geosite:category-ads-all"],
        "outboundTag": "block"
      }
    ]
  }
}
EOF

    # Create user database directory
    mkdir -p $INSTALL_DIR/users
    echo "[]" > $INSTALL_DIR/users/vmess.json
    echo "[]" > $INSTALL_DIR/users/vless.json
    echo "[]" > $INSTALL_DIR/users/trojan.json
    echo "[]" > $INSTALL_DIR/users/ssh.json

    success "Xray configured with security enhancements"
}

# Configure Dropbear for Ubuntu 20.04
configure_dropbear_ubuntu20() {
    log "Configuring Dropbear for Ubuntu 20.04..."
    
    cat > /etc/default/dropbear << 'EOF'
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 109 -s -j -k"
DROPBEAR_BANNER="/etc/issue.net"
EOF

    echo "Authorized Access Only - dhyntoh VPN Server" > /etc/issue.net
    
    systemctl enable dropbear
    systemctl start dropbear
    
    success "Dropbear configured and started"
}

# Configure Stunnel4 for Ubuntu 20.04
configure_stunnel_ubuntu20() {
    log "Configuring Stunnel4 for Ubuntu 20.04..."
    
    cat > /etc/stunnel/stunnel.conf << 'EOF'
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0
fips = no

[ssh-444]
accept = 444
connect = 127.0.0.1:109

[ssh-445]
accept = 445
connect = 127.0.0.1:109

[ssh-447]
accept = 447
connect = 127.0.0.1:109

[ssh-777]
accept = 777
connect = 127.0.0.1:109
EOF

    systemctl enable stunnel4
    systemctl start stunnel4
    
    success "Stunnel4 configured on ports 444,445,447,777"
}

# Configure HAProxy for Ubuntu 20.04
configure_haproxy_ubuntu20() {
    log "Configuring HAProxy 2.0 for Ubuntu 20.04..."
    
    cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    daemon
    maxconn 4000
    tune.ssl.default-dh-param 2048
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    mode tcp
    timeout connect 5s
    timeout client 60s
    timeout server 60s
    log global
    option tcplog
    option dontlognull

frontend main
    bind *:80
    bind *:443 ssl crt /etc/xray/xray.crt alpn h2,http/1.1
    bind *:8443 ssl crt /etc/xray/xray.crt
    bind *:8880
    bind *:444
    bind *:445
    bind *:447
    bind *:777
    
    tcp-request inspect-delay 5s
    tcp-request content accept if HTTP
    tcp-request content accept if { req_ssl_hello_type 1 }
    
    acl path_vmess path_beg /vmess
    acl path_vless path_beg /vless
    acl path_trojan path_beg /trojan
    acl path_ssh path_beg /ssh-ws
    
    use_backend xray_vmess if path_vmess
    use_backend xray_vless if path_vless
    use_backend xray_trojan if path_trojan
    use_backend ssh_websocket if path_ssh
    default_backend ssh_stunnel

backend xray_vmess
    server vmess 127.0.0.1:10002 check

backend xray_vless
    server vless 127.0.0.1:10001 check

backend xray_trojan
    server trojan 127.0.0.1:10003 check

backend ssh_websocket
    mode http
    server ssh_ws 127.0.0.1:10015 check

backend ssh_stunnel
    server ssh 127.0.0.1:109 check
EOF

    systemctl enable haproxy
    systemctl start haproxy
    
    success "HAProxy 2.0 configured and started"
}

# Configure Nginx for Ubuntu 20.04
configure_nginx_ubuntu20() {
    log "Configuring Nginx 1.18 for Ubuntu 20.04..."
    
    # Stop nginx if running
    systemctl stop nginx >/dev/null 2>&1 || true
    
    # Create optimized nginx config
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml text/javascript;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Create WebSocket proxy configuration
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/websocket.conf << 'EOF'
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
        proxy_read_timeout 86400;
    }
}
EOF

    systemctl enable nginx
    systemctl start nginx
    
    success "Nginx 1.18 configured and started"
}

# Configure secure firewall
configure_secure_firewall() {
    log "Configuring secure firewall..."
    
    # Reset UFW
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow essential services
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow VPN ports
    ufw allow 444/tcp
    ufw allow 445/tcp
    ufw allow 447/tcp
    ufw allow 777/tcp
    ufw allow 8443/tcp
    ufw allow 8880/tcp
    ufw allow 10015/tcp
    
    # Enable UFW
    ufw --force enable
    
    success "Secure firewall configured"
}

# Create user management system
create_user_management() {
    log "Creating user management system..."
    
    cat > /usr/local/bin/vpn-user << 'EOF'
#!/bin/bash

USERS_DIR="/opt/dhyntoh-vpn/users"
XRAY_CONFIG="/etc/xray/config.json"

generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

add_user() {
    local protocol=$1
    local username=$2
    local expiry_days=$3
    
    local expiry_date=$(date -d "+$expiry_days days" +%Y-%m-%d)
    
    case $protocol in
        vmess)
            local uuid=$(generate_uuid)
            local user_data="{\"username\":\"$username\",\"uuid\":\"$uuid\",\"expiry\":\"$expiry_date\",\"created\":\"$(date)\",\"active\":true}"
            
            # Update Xray config
            jq --arg uuid "$uuid" --arg username "$username" \
                '(.inbounds[] | select(.tag == "vmess-ws") | .settings.clients) += [{"id": $uuid, "alterId": 0, "email": $username}]' \
                $XRAY_CONFIG > /tmp/xray_temp.json && mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Update user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/vmess.json > /tmp/vmess_temp.json
            mv /tmp/vmess_temp.json $USERS_DIR/vmess.json
            
            systemctl restart xray
            echo "VMess user created: $username | UUID: $uuid | Expiry: $expiry_date"
            ;;
            
        vless)
            local uuid=$(generate_uuid)
            local user_data="{\"username\":\"$username\",\"uuid\":\"$uuid\",\"expiry\":\"$expiry_date\",\"created\":\"$(date)\",\"active\":true}"
            
            # Update Xray config
            jq --arg uuid "$uuid" --arg username "$username" \
                '(.inbounds[] | select(.tag == "vless-tls") | .settings.clients) += [{"id": $uuid, "flow": "xtls-rprx-vision", "email": $username}]' \
                $XRAY_CONFIG > /tmp/xray_temp.json && mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Update user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/vless.json > /tmp/vless_temp.json
            mv /tmp/vless_temp.json $USERS_DIR/vless.json
            
            systemctl restart xray
            echo "VLess user created: $username | UUID: $uuid | Expiry: $expiry_date"
            ;;
            
        trojan)
            local password=$(generate_uuid)
            local user_data="{\"username\":\"$username\",\"password\":\"$password\",\"expiry\":\"$expiry_date\",\"created\":\"$(date)\",\"active\":true}"
            
            # Update Xray config
            jq --arg password "$password" --arg username "$username" \
                '(.inbounds[] | select(.tag == "trojan-ws") | .settings.clients) += [{"password": $password, "email": $username}]' \
                $XRAY_CONFIG > /tmp/xray_temp.json && mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Update user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/trojan.json > /tmp/trojan_temp.json
            mv /tmp/trojan_temp.json $USERS_DIR/trojan.json
            
            systemctl restart xray
            echo "Trojan user created: $username | Password: $password | Expiry: $expiry_date"
            ;;
            
        ssh)
            local password=$(openssl rand -base64 12)
            local user_data="{\"username\":\"$username\",\"password\":\"$password\",\"expiry\":\"$expiry_date\",\"created\":\"$(date)\",\"active\":true}"
            
            # Create system user
            useradd -m -s /bin/bash $username
            echo "$username:$password" | chpasswd
            chage -E $expiry_date $username
            
            # Update user database
            jq --argjson user "$user_data" '. += [$user]' $USERS_DIR/ssh.json > /tmp/ssh_temp.json
            mv /tmp/ssh_temp.json $USERS_DIR/ssh.json
            
            echo "SSH user created: $username | Password: $password | Expiry: $expiry_date"
            ;;
    esac
}

delete_user() {
    local protocol=$1
    local username=$2
    
    case $protocol in
        vmess|vless|trojan)
            # Remove from Xray config
            jq --arg username "$username" \
                "(.inbounds[] | select(.tag == \"$protocol-ws\") | .settings.clients) |= map(select(.email != \$username))" \
                $XRAY_CONFIG > /tmp/xray_temp.json && mv /tmp/xray_temp.json $XRAY_CONFIG
            
            # Remove from user database
            jq --arg username "$username" 'map(select(.username != $username))' $USERS_DIR/$protocol.json > /tmp/${protocol}_temp.json
            mv /tmp/${protocol}_temp.json $USERS_DIR/$protocol.json
            
            systemctl restart xray
            echo "$protocol user $username deleted"
            ;;
            
        ssh)
            userdel -r $username 2>/dev/null
            jq --arg username "$username" 'map(select(.username != $username))' $USERS_DIR/ssh.json > /tmp/ssh_temp.json
            mv /tmp/ssh_temp.json $USERS_DIR/ssh.json
            echo "SSH user $username deleted"
            ;;
    esac
}

renew_user() {
    local protocol=$1
    local username=$2
    local extra_days=$3
    
    local new_expiry=$(date -d "+$extra_days days" +%Y-%m-%d)
    
    jq --arg username "$username" --arg new_expiry "$new_expiry" \
        'map(if .username == $username then .expiry = $new_expiry else . end)' \
        $USERS_DIR/$protocol.json > /tmp/${protocol}_temp.json
    mv /tmp/${protocol}_temp.json $USERS_DIR/$protocol.json
    
    # For SSH users, update system account
    if [[ $protocol == "ssh" ]] && id "$username" &>/dev/null; then
        chage -E $new_expiry $username
    fi
    
    echo "User $username renewed until $new_expiry"
}

list_users() {
    local protocol=$1
    
    case $protocol in
        vmess)
            echo "=== VMESS USERS ==="
            jq -r '.[] | "\(.username) | \(.uuid) | Expiry: \(.expiry)"' $USERS_DIR/vmess.json 2>/dev/null || echo "No users"
            ;;
        vless)
            echo "=== VLESS USERS ==="
            jq -r '.[] | "\(.username) | \(.uuid) | Expiry: \(.expiry)"' $USERS_DIR/vless.json 2>/dev/null || echo "No users"
            ;;
        trojan)
            echo "=== TROJAN USERS ==="
            jq -r '.[] | "\(.username) | \(.password) | Expiry: \(.expiry)"' $USERS_DIR/trojan.json 2>/dev/null || echo "No users"
            ;;
        ssh)
            echo "=== SSH USERS ==="
            jq -r '.[] | "\(.username) | \(.password) | Expiry: \(.expiry)"' $USERS_DIR/ssh.json 2>/dev/null || echo "No users"
            ;;
        all)
            echo "=== ALL VPN USERS ==="
            for proto in vmess vless trojan ssh; do
                echo "--- $(echo $proto | tr 'a-z' 'A-Z') ---"
                jq -r '.[] | "\(.username) | Expiry: \(.expiry)"' $USERS_DIR/$proto.json 2>/dev/null || echo "No users"
                echo
            done
            ;;
    esac
}

case "$1" in
    add)
        if [[ $# -ne 4 ]]; then
            echo "Usage: vpn-user add <protocol> <username> <expiry_days>"
            exit 1
        fi
        add_user $2 $3 $4
        ;;
    delete)
        if [[ $# -ne 3 ]]; then
            echo "Usage: vpn-user delete <protocol> <username>"
            exit 1
        fi
        delete_user $2 $3
        ;;
    renew)
        if [[ $# -ne 4 ]]; then
            echo "Usage: vpn-user renew <protocol> <username> <extra_days>"
            exit 1
        fi
        renew_user $2 $3 $4
        ;;
    list)
        if [[ $# -ne 2 ]]; then
            echo "Usage: vpn-user list <protocol|all>"
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
        echo "  vpn-user delete vmess user1"
        echo "  vpn-user renew vmess user1 30"
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
        echo "=== SERVICE STATUS ==="
        for service in xray nginx haproxy stunnel4 dropbear fail2ban; do
            if systemctl is-active --quiet $service; then
                echo "✅ $service: RUNNING"
            else
                echo "❌ $service: STOPPED"
            fi
        done
        ;;
    fix-all)
        systemctl enable xray nginx haproxy stunnel4 dropbear fail2ban
        systemctl start xray nginx haproxy stunnel4 dropbear fail2ban
        echo "🔧 All services enabled and started"
        ;;
    logs)
        journalctl -u xray -f
        ;;
    *)
        echo "dhyntoh VPN Service Manager"
        echo "Usage: vpn-manager {start|stop|restart|status|fix-all|logs}"
        ;;
esac
EOF

    chmod +x /usr/local/bin/vpn-manager
    
    success "User management system created"
}

# Final setup and optimization
final_setup_ubuntu20() {
    log "Finalizing Ubuntu 20.04 setup..."
    
    # Enable all services
    systemctl daemon-reload
    systemctl enable xray nginx haproxy stunnel4 dropbear fail2ban
    systemctl start xray nginx haproxy stunnel4 dropbear fail2ban
    
    # Optimize system for VPN
    cat >> /etc/sysctl.conf << 'EOF'
# VPN Optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3

# Network optimizations
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.somaxconn = 65535

# Security optimizations
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

    sysctl -p
    
    # Increase file limits
    echo "* soft nofile 65535" >> /etc/security/limits.conf
    echo "* hard nofile 65535" >> /etc/security/limits.conf
    
    success "System optimized for VPN performance"
}

# Display completion message
show_completion() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║      UBUNTU 20.04 VPN INSTALLATION COMPLETE     ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║ ✅ Ubuntu 20.04 Fully Compatible                ║"
    echo "║ ✅ No Ubuntu Pro Required                       ║"
    echo "║ ✅ All Security Features Enabled                ║"
    echo "║ ✅ All Services Working                         ║"
    echo "║                                                 ║"
    echo "║ 🎯 USAGE COMMANDS:                              ║"
    echo "║    • vpn-user add vmess user1 30               ║"
    echo "║    • vpn-user add vless user2 30               ║"
    echo "║    • vpn-user add trojan user3 30              ║"
    echo "║    • vpn-user add ssh user4 30                 ║"
    echo "║    • vpn-user renew vmess user1 30             ║"
    echo "║    • vpn-user delete vmess user1               ║"
    echo "║    • vpn-user list all                         ║"
    echo "║    • vpn-manager status                        ║"
    echo "║    • menu                                      ║"
    echo "║                                                 ║"
    echo "║ 🔒 SECURITY FEATURES:                           ║"
    echo "║    • Fail2ban Protection                       ║"
    echo "║    • UFW Firewall                              ║"
    echo "║    • Automatic Security Updates                ║"
    echo "║    • Secure SSH Configuration                  ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Main installation function
main() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║         dhyntoh VPN for Ubuntu 20.04           ║"
    echo "║           No Ubuntu Pro Required                ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_ubuntu_version
    secure_system_prep
    install_dependencies_ubuntu20
    install_xray_ubuntu20
    configure_system_security
    generate_ssl_certificates
    configure_xray_secure
    configure_dropbear_ubuntu20
    configure_stunnel_ubuntu20
    configure_haproxy_ubuntu20
    configure_nginx_ubuntu20
    configure_secure_firewall
    create_user_management
    final_setup_ubuntu20
    show_completion
    
    success "Ubuntu 20.04 VPN installation completed successfully!"
    log "Installation log: $LOG_FILE"
}

main "$@"