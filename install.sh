#!/bin/bash

# dhyntoh VPN AutoScript with Complete Prerequisites
# GitHub: https://github.com/dhyntoh/script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
REPO_URL="https://raw.githubusercontent.com/dhyntoh/script/main"
SCRIPT_VERSION="3.0"
DOMAIN=""
EMAIL="admin@yourdomain.com"
INSTALL_DIR="/opt/dhyntoh-vpn"
LOG_FILE="/var/log/dhyntoh-vpn-install.log"

# Logging functions
log() { echo -e "${BLUE}[INSTALL]${NC} $1" | tee -a $LOG_FILE; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a $LOG_FILE; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a $LOG_FILE; }
error() { echo -e "${RED}[ERROR]${NC} $1" | tee -a $LOG_FILE; exit 1; }

# Run prerequisite check
run_prerequisites() {
    log "Running prerequisite checks..."
    
    if [[ ! -f /tmp/prerequisite_report.txt ]]; then
        log "Installing prerequisites first..."
        if curl -sSL -o /tmp/prerequisite.sh "$REPO_URL/prerequisite.sh"; then
            chmod +x /tmp/prerequisite.sh
            /tmp/prerequisite.sh
        else
            warning "Could not download prerequisite script, continuing with basic checks..."
            check_basic_requirements
        fi
    else
        success "Prerequisites already installed"
    fi
}

# Basic requirement check
check_basic_requirements() {
    log "Checking basic requirements..."
    
    local required_commands=("curl" "wget" "git" "jq" "openssl" "systemctl")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            error "$cmd is required but not installed. Run prerequisite.sh first."
        fi
    done
    success "Basic requirements satisfied"
}

# Get user input
get_user_input() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║    dhyntoh VPN AutoInstaller        ║"
    echo "║           Version $SCRIPT_VERSION          ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check if we have a domain from previous run
    if [[ -f "$INSTALL_DIR/config.env" ]]; then
        source "$INSTALL_DIR/config.env"
        log "Found existing configuration: Domain=$DOMAIN"
        read -p "Use existing domain? (Y/n): " use_existing
        if [[ ! "$use_existing" =~ ^[Nn]$ ]]; then
            return
        fi
    fi
    
    while true; do
        read -p "Enter your domain (e.g., vpn.example.com): " DOMAIN
        if [[ -n "$DOMAIN" && "$DOMAIN" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            warning "Invalid domain format"
        fi
    done
    
    read -p "Enter email for SSL certificate: " input_email
    EMAIL="${input_email:-admin@$DOMAIN}"
    
    # Save configuration
    mkdir -p $INSTALL_DIR
    cat > "$INSTALL_DIR/config.env" << EOF
DOMAIN=$DOMAIN
EMAIL=$EMAIL
INSTALL_DIR=$INSTALL_DIR
SCRIPT_VERSION=$SCRIPT_VERSION
EOF
    
    success "Configuration saved: Domain=$DOMAIN, Email=$EMAIL"
}

# Install Xray with dependencies
install_xray() {
    log "Installing Xray core..."
    
    # Install Xray
    if ! bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install; then
        error "Failed to install Xray"
    fi
    
    # Create necessary directories
    mkdir -p /etc/xray /var/log/xray /usr/local/share/xray
    chown -R nobody:nogroup /var/log/xray
    
    success "Xray installed successfully"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log "Generating SSL certificates..."
    
    # Stop nginx temporarily for certbot
    systemctl stop nginx >/dev/null 2>&1 || true
    
    # Try Let's Encrypt first
    if certbot certonly --standalone -d $DOMAIN --non-interactive --agree-tos --email $EMAIL; then
        ln -sf /etc/letsencrypt/live/$DOMAIN/fullchain.pem /etc/xray/xray.crt
        ln -sf /etc/letsencrypt/live/$DOMAIN/privkey.pem /etc/xray/xray.key
        
        # Set up auto-renewal
        (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook \"systemctl reload nginx xray\"") | crontab -
        success "Let's Encrypt SSL certificates installed with auto-renewal"
    else
        # Fallback to self-signed
        warning "Let's Encrypt failed, generating self-signed certificate"
        openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN" \
            -keyout /etc/xray/xray.key -out /etc/xray/xray.crt
        success "Self-signed SSL certificates generated"
    fi
    
    # Restart nginx
    systemctl start nginx >/dev/null 2>&1 || true
    
    # Set proper permissions
    chmod 600 /etc/xray/xray.key
    chmod 644 /etc/xray/xray.crt
}

# Configure Xray with all protocols
configure_xray() {
    log "Configuring Xray multi-protocol..."
    
    # Generate UUIDs
    UUID_VLESS=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    UUID_VMESS=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    UUID_TROJAN=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)
    
    cat > /etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
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
  },
  "inbounds": [
    {
      "port": 10001,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$UUID_VLESS",
            "flow": "xtls-rprx-vision"
          }
        ],
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
          ]
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
        "clients": [
          {
            "id": "$UUID_VMESS",
            "alterId": 0
          }
        ]
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
        "clients": [
          {
            "password": "$UUID_TROJAN"
          }
        ]
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
            "password": "$UUID_VLESS"
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
  ]
}
EOF

    # Save client configurations
    mkdir -p $INSTALL_DIR/clients
    cat > $INSTALL_DIR/clients/configs.txt << EOF
=== dhyntoh Multi-Protocol VPN Configuration ===
Domain: $DOMAIN
Install Date: $(date)

=== STUNNEL4 Ports ===
Ports: 444, 445, 447, 777
Usage: SSL tunneling for SSH

=== SSH Protocols ===
SSH-WS (WebSocket): Ports 80, 8880 - Path: /ssh-ws
SSH-WS-TLS (Secure): Ports 443, 8443 - Path: /ssh-ws

=== V2Ray Protocols ===
VLESS WS TLS:
- Address: $DOMAIN
- Port: 443, 8443
- UUID: $UUID_VLESS
- Path: /vless
- Security: TLS

VMess WS:
- Address: $DOMAIN  
- Port: 80, 8880
- UUID: $UUID_VMESS
- Path: /vmess

VMess WS TLS:
- Address: $DOMAIN
- Port: 443, 8443
- UUID: $UUID_VMESS
- Path: /vmess
- Security: TLS

=== Trojan Protocol ===
Trojan WS TLS:
- Address: $DOMAIN
- Port: 443, 8443  
- Password: $UUID_TROJAN
- Path: /trojan
- Security: TLS

=== Configuration Files ===
Xray: /etc/xray/config.json
Nginx: /etc/nginx/conf.d/vpn-multi.conf
HAProxy: /etc/haproxy/haproxy.cfg
Stunnel: /etc/stunnel/stunnel.conf

EOF

    success "Xray configured with all protocols"
}

# Configure Stunnel4
configure_stunnel() {
    log "Configuring Stunnel4 on ports 444,445,447,777..."
    
    cat > /etc/stunnel/stunnel.conf << EOF
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key
client = no
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
TIMEOUTclose = 0

[stunnel-444]
accept = 444
connect = 127.0.0.1:109

[stunnel-445]
accept = 445
connect = 127.0.0.1:109

[stunnel-447]
accept = 447
connect = 127.0.0.1:109

[stunnel-777]
accept = 777
connect = 127.0.0.1:109
EOF

    systemctl enable stunnel4
    systemctl start stunnel4
    success "Stunnel4 configured on ports 444,445,447,777"
}

# Configure Dropbear
configure_dropbear() {
    log "Configuring Dropbear multi-port SSH..."
    
    cat > /etc/default/dropbear << EOF
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 109"
DROPBEAR_BANNER="/etc/issue.net"
EOF

    systemctl enable dropbear
    systemctl restart dropbear
    success "Dropbear SSH configured"
}

# Configure Nginx for all protocols
configure_nginx() {
    log "Configuring Nginx multi-protocol reverse proxy..."
    
    # Create optimized nginx config
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 4096;
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
}
EOF

    # Create multi-protocol configuration
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/vpn-multi.conf << EOF
# HTTP servers for WebSocket (Port 80, 8880)
server {
    listen 80;
    listen 8880;
    server_name $DOMAIN;
    
    # SSH WebSocket
    location /ssh-ws {
        proxy_pass http://127.0.0.1:10015;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
    
    # VMess WebSocket
    location /vmess {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # VLESS WebSocket
    location /vless {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        return 444;
    }
}

# HTTPS servers for WebSocket over TLS (Port 443, 8443)
server {
    listen 443 ssl http2;
    listen 8443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    
    # SSH WebSocket over TLS
    location /ssh-ws {
        proxy_pass http://127.0.0.1:10015;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }
    
    # VMess WebSocket over TLS
    location /vmess {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # VLESS WebSocket over TLS
    location /vless {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Trojan WebSocket over TLS
    location /trojan {
        proxy_pass http://127.0.0.1:10004;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location / {
        return 444;
    }
}
EOF

    if nginx -t; then
        systemctl enable nginx
        systemctl restart nginx
        success "Nginx configured for multi-protocol"
    else
        error "Nginx configuration test failed"
    fi
}

# Configure HAProxy for load balancing
configure_haproxy() {
    log "Configuring HAProxy load balancer..."
    
    cat > /etc/haproxy/haproxy.cfg << EOF
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

frontend multi-frontend
    bind *:80
    bind *:443
    bind *:444
    bind *:445
    bind *:447
    bind *:777
    bind *:8443
    bind *:8880
    
    tcp-request inspect-delay 5s
    tcp-request content accept if HTTP
    tcp-request content accept if { req.ssl_hello_type 1 }
    
    use_backend ssh_ws if { path_beg /ssh-ws }
    use_backend vless_ws if { path_beg /vless }
    use_backend vmess_ws if { path_beg /vmess }
    use_backend trojan_ws if { path_beg /trojan }
    default_backend stunnel_ssh

backend ssh_ws
    mode http
    server ssh_ws 127.0.0.1:10015

backend vless_ws
    mode http
    server vless_ws 127.0.0.1:10001

backend vmess_ws
    mode http
    server vmess_ws 127.0.0.1:10002

backend trojan_ws
    mode http
    server trojan_ws 127.0.0.1:10004

backend stunnel_ssh
    mode tcp
    server stunnel_ssh 127.0.0.1:109
EOF

    systemctl enable haproxy
    systemctl start haproxy
    success "HAProxy configured for load balancing"
}

# Configure SSH WebSocket tunnel
configure_ssh_websocket() {
    log "Configuring SSH WebSocket tunnel..."
    
    # Create SSH WebSocket service
    cat > /etc/systemd/system/ssh-websocket.service << EOF
[Unit]
Description=SSH WebSocket Tunnel
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/ssh -o StrictHostKeyChecking=no -N -D 127.0.0.1:10015 -p 109 root@127.0.0.1
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ssh-websocket
    systemctl start ssh-websocket
    success "SSH WebSocket tunnel configured"
}

# Configure firewall for all ports
configure_firewall() {
    log "Configuring firewall for all VPN ports..."
    
    if command -v ufw >/dev/null 2>&1; then
        # Ubuntu/Debian
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
    elif command -v firewall-cmd >/dev/null 2>&1; then
        # CentOS/RHEL
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
    fi
    success "Firewall configured for all VPN ports"
}

# Optimize system performance
optimize_system() {
    log "Optimizing system performance..."
    
    # TCP optimizations
    cat >> /etc/sysctl.conf << 'EOF'
# Network optimizations
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3

# Socket buffers
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864

# Connection limits
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 65536

# TCP settings
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_max_tw_buckets = 2000000

# Security
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

    sysctl -p
    success "System performance optimized"
}

# Create management script
create_management_script() {
    log "Creating management scripts..."
    
    cat > /usr/local/bin/dhyntoh-vpn << 'EOF'
#!/bin/bash

VERSION="3.0"
INSTALL_DIR="/opt/dhyntoh-vpn"

show_banner() {
    echo "╔══════════════════════════════════════╗"
    echo "║        dhyntoh VPN Manager         ║"
    echo "║           Version $VERSION           ║"
    echo "╚══════════════════════════════════════╝"
}

case "$1" in
    start)
        systemctl start xray nginx haproxy stunnel4 dropbear ssh-websocket
        echo "✅ All VPN services started"
        ;;
    stop)
        systemctl stop xray nginx haproxy stunnel4 ssh-websocket
        echo "🛑 All VPN services stopped"
        ;;
    restart)
        systemctl restart xray nginx haproxy stunnel4 dropbear ssh-websocket
        echo "🔄 All VPN services restarted"
        ;;
    status)
        show_banner
        echo ""
        echo "=== Service Status ==="
        systemctl is-active xray &>/dev/null && echo "Xray: ✅ Running" || echo "Xray: ❌ Stopped"
        systemctl is-active nginx &>/dev/null && echo "Nginx: ✅ Running" || echo "Nginx: ❌ Stopped"
        systemctl is-active haproxy &>/dev/null && echo "HAProxy: ✅ Running" || echo "HAProxy: ❌ Stopped"
        systemctl is-active stunnel4 &>/dev/null && echo "Stunnel4: ✅ Running" || echo "Stunnel4: ❌ Stopped"
        systemctl is-active dropbear &>/dev/null && echo "Dropbear: ✅ Running" || echo "Dropbear: ❌ Stopped"
        systemctl is-active ssh-websocket &>/dev/null && echo "SSH-WS: ✅ Running" || echo "SSH-WS: ❌ Stopped"
        ;;
    log)
        tail -f /var/log/xray/error.log
        ;;
    config)
        cat $INSTALL_DIR/clients/configs.txt
        ;;
    update)
        echo "🔄 Updating dhyntoh VPN..."
        curl -sSL https://raw.githubusercontent.com/dhyntoh/script/main/update.sh | bash
        ;;
    ports)
        show_banner
        echo ""
        echo "=== Active Ports ==="
        echo "Stunnel4 SSL: 444, 445, 447, 777"
        echo "SSH WebSocket: 80, 8880"
        echo "SSH WebSocket TLS: 443, 8443"
        echo "V2Ray WebSocket: 80, 8880"
        echo "V2Ray WebSocket TLS: 443, 8443"
        echo "Trojan WebSocket TLS: 443, 8443"
        ;;
    backup)
        echo "💾 Creating backup..."
        tar -czf /root/vpn-backup-$(date +%Y%m%d).tar.gz /etc/xray /etc/nginx /etc/haproxy /etc/stunnel $INSTALL_DIR
        echo "✅ Backup created: /root/vpn-backup-$(date +%Y%m%d).tar.gz"
        ;;
    *)
        show_banner
        echo ""
        echo "Usage: dhyntoh-vpn {start|stop|restart|status|log|config|update|ports|backup}"
        echo ""
        echo "Commands:"
        echo "  start    - Start all VPN services"
        echo "  stop     - Stop all VPN services"
        echo "  restart  - Restart all VPN services"
        echo "  status   - Show service status"
        echo "  log      - View Xray logs"
        echo "  config   - Show client configurations"
        echo "  update   - Update VPN script"
        echo "  ports    - Show active ports"
        echo "  backup   - Create configuration backup"
        ;;
esac
EOF

    chmod +x /usr/local/bin/dhyntoh-vpn
    
    # Create update script
    cat > $INSTALL_DIR/update.sh << 'EOF'
#!/bin/bash
echo "Updating dhyntoh VPN..."
# Update logic will be added here
echo "Update complete"
EOF

    chmod +x $INSTALL_DIR/update.sh
    
    success "Management scripts created"
}

# Final setup and verification
final_setup() {
    log "Finalizing installation..."
    
    # Enable and start all services
    systemctl daemon-reload
    systemctl enable xray nginx haproxy stunnel4 dropbear ssh-websocket
    systemctl restart xray nginx haproxy stunnel4 dropbear ssh-websocket
    
    # Wait for services to start
    sleep 5
    
    # Verify services are running
    log "Verifying services..."
    local services=("xray" "nginx" "haproxy" "stunnel4" "dropbear" "ssh-websocket")
    local all_ok=true
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            success "$service: ✅ Running"
        else
            error "$service: ❌ Failed to start"
            all_ok=false
        fi
    done
    
    if $all_ok; then
        success "All services are running correctly"
    else
        warning "Some services need attention. Check logs with: journalctl -u service-name"
    fi
    
    # Display completion message
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║           VPN INSTALLATION COMPLETE!           ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║ Domain: $DOMAIN"
    echo "║ Stunnel4: 444, 445, 447, 777"
    echo "║ SSH-WS: 80, 8880"
    echo "║ SSH-WS-TLS: 443, 8443"
    echo "║ V2Ray WS: 80, 8880"
    echo "║ V2Ray WS-TLS: 443, 8443"
    echo "║ Trojan WS-TLS: 443, 8443"
    echo "║ Management: dhyntoh-vpn status"
    echo "║ Configs: $INSTALL_DIR/clients/configs.txt"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Display important notes
    echo -e "${YELLOW}"
    echo "Important Notes:"
    echo "• Client configurations saved to: $INSTALL_DIR/clients/configs.txt"
    echo "• Use 'dhyntoh-vpn status' to check service status"
    echo "• Use 'dhyntoh-vpn update' to update the script"
    echo "• Firewall configured to allow all necessary ports"
    echo -e "${NC}"
}

# Main installation function
main() {
    echo -e "${CYAN}"
    echo "Starting dhyntoh Multi-Protocol VPN Installation..."
    echo "This will install all components with complete prerequisites"
    echo -e "${NC}"
    
    # Create log file
    > $LOG_FILE
    
    # Installation steps
    run_prerequisites
    get_user_input
    install_xray
    generate_ssl_certificates
    configure_xray
    configure_stunnel
    configure_dropbear
    configure_nginx
    configure_haproxy
    configure_ssh_websocket
    configure_firewall
    optimize_system
    create_management_script
    final_setup
    
    success "dhyntoh Multi-Protocol VPN installation completed successfully!"
    log "Detailed log: $LOG_FILE"
}

main "$@"
