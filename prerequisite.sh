#!/bin/bash

# dhyntoh VPN Prerequisite Checker
# Checks and installs all required components before main installation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log() { echo -e "${BLUE}[PREREQ]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS and version
detect_os() {
    log "Detecting operating system..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_NAME=$PRETTY_NAME
    elif [[ -f /etc/redhat-release ]]; then
        OS="centos"
        OS_VERSION=$(grep -oE '[0-9]+\.[0-9]+' /etc/redhat-release)
        OS_NAME=$(cat /etc/redhat-release)
    else
        error "Cannot detect operating system"
    fi
    
    success "Detected: $OS_NAME"
}

# Check system requirements
check_system_requirements() {
    log "Checking system requirements..."
    
    # Check RAM
    local RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local RAM_MB=$((RAM_KB / 1024))
    local RAM_GB=$((RAM_MB / 1024))
    
    if [[ $RAM_MB -lt 512 ]]; then
        warning "Low RAM: ${RAM_MB}MB (Recommended: 1GB+)"
    else
        success "RAM: ${RAM_GB}GB"
    fi
    
    # Check disk space
    local DISK_KB=$(df / | tail -1 | awk '{print $4}')
    local DISK_GB=$((DISK_KB / 1024 / 1024))
    
    if [[ $DISK_GB -lt 5 ]]; then
        warning "Low disk space: ${DISK_GB}GB (Recommended: 10GB+)"
    else
        success "Disk space: ${DISK_GB}GB"
    fi
    
    # Check architecture
    local ARCH=$(uname -m)
    if [[ "$ARCH" =~ ^(x86_64|aarch64)$ ]]; then
        success "Architecture: $ARCH"
    else
        warning "Uncommon architecture: $ARCH (May have compatibility issues)"
    fi
    
    # Check kernel version
    local KERNEL=$(uname -r)
    success "Kernel: $KERNEL"
}

# Install base system utilities
install_base_utilities() {
    log "Installing base system utilities..."
    
    case $OS in
        ubuntu|debian)
            apt update && apt upgrade -y
            apt install -y sudo curl wget git gnupg2 lsb-release \
                         software-properties-common apt-transport-https \
                         ca-certificates ufw >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum update -y
            yum install -y sudo curl wget git epel-release \
                         yum-utils firewalld >> /dev/null 2>&1
            ;;
    esac
    success "Base utilities installed"
}

# Install development tools
install_development_tools() {
    log "Installing development tools..."
    
    case $OS in
        ubuntu|debian)
            apt install -y build-essential gcc g++ make cmake \
                         autoconf automake libtool pkg-config \
                         python3 python3-pip python3-venv >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum groupinstall -y "Development Tools"
            yum install -y gcc-c++ make cmake autoconf automake \
                         libtool pkgconfig python3 python3-pip >> /dev/null 2>&1
            ;;
    esac
    success "Development tools installed"
}

# Install network utilities
install_network_utilities() {
    log "Installing network utilities..."
    
    case $OS in
        ubuntu|debian)
            apt install -y net-tools iproute2 dnsutils traceroute \
                         iperf3 tcpdump nmap netcat-openbsd socat \
                         openssh-client openssh-server >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y net-tools iproute bind-utils traceroute \
                         iperf3 tcpdump nmap nc socat openssh-clients \
                         openssh-server >> /dev/null 2>&1
            ;;
    esac
    success "Network utilities installed"
}

# Install SSL and security tools
install_security_tools() {
    log "Installing SSL and security tools..."
    
    case $OS in
        ubuntu|debian)
            apt install -y openssl stunnel4 dropbear fail2ban \
                         certbot python3-certbot-nginx >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y openssl stunnel dropbear fail2ban \
                         certbot python3-certbot-nginx >> /dev/null 2>&1
            ;;
    esac
    success "Security tools installed"
}

# Install web servers and proxies
install_web_servers() {
    log "Installing web servers and proxies..."
    
    case $OS in
        ubuntu|debian)
            apt install -y nginx haproxy apache2-utils >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y nginx haproxy httpd-tools >> /dev/null 2>&1
            ;;
    esac
    success "Web servers installed"
}

# Install database and caching (if needed)
install_database_tools() {
    log "Installing database tools..."
    
    case $OS in
        ubuntu|debian)
            apt install -y sqlite3 redis-server >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y sqlite redis >> /dev/null 2>&1
            ;;
    esac
    success "Database tools installed"
}

# Install monitoring tools
install_monitoring_tools() {
    log "Installing monitoring tools..."
    
    case $OS in
        ubuntu|debian)
            apt install -y htop atop iotop iftop nmon dstat \
                         sysstat logrotate >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y htop atop iotop iftop nmon dstat \
                         sysstat logrotate >> /dev/null 2>&1
            ;;
    esac
    success "Monitoring tools installed"
}

# Install text processing tools
install_text_tools() {
    log "Installing text processing tools..."
    
    case $OS in
        ubuntu|debian)
            apt install -y jq bc awk sed grep findutils \
                         tree vim nano less >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y jq bc awk sed grep findutils \
                         tree vim nano less >> /dev/null 2>&1
            ;;
    esac
    success "Text processing tools installed"
}

# Install compression tools
install_compression_tools() {
    log "Installing compression tools..."
    
    case $OS in
        ubuntu|debian)
            apt install -y bzip2 gzip zip unzip tar xz-utils >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y bzip2 gzip zip unzip tar xz >> /dev/null 2>&1
            ;;
    esac
    success "Compression tools installed"
}

# Install version control
install_version_control() {
    log "Installing version control..."
    
    case $OS in
        ubuntu|debian)
            apt install -y git subversion >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y git subversion >> /dev/null 2>&1
            ;;
    esac
    success "Version control installed"
}

# Install process management
install_process_management() {
    log "Installing process management tools..."
    
    case $OS in
        ubuntu|debian)
            apt install -y cron anacron systemd-sysv >> /dev/null 2>&1
            systemctl enable cron
            ;;
        centos|rhel|fedora)
            yum install -y cronie systemd >> /dev/null 2>&1
            systemctl enable crond
            ;;
    esac
    success "Process management tools installed"
}

# Install time synchronization
install_time_sync() {
    log "Installing time synchronization..."
    
    case $OS in
        ubuntu|debian)
            apt install -y ntp ntpdate systemd-timesyncd >> /dev/null 2>&1
            systemctl enable ntp
            ;;
        centos|rhel|fedora)
            yum install -y ntp ntpdate chrony >> /dev/null 2>&1
            systemctl enable ntpd
            ;;
    esac
    
    # Set timezone to UTC
    timedatectl set-timezone UTC
    success "Time synchronization configured"
}

# Configure system limits
configure_system_limits() {
    log "Configuring system limits..."
    
    cat >> /etc/security/limits.conf << 'EOF'
* soft nofile 65536
* hard nofile 65536
* soft nproc 65536
* hard nproc 65536
root soft nofile 65536
root hard nofile 65536
EOF

    cat >> /etc/sysctl.conf << 'EOF'
# Increase system limits
fs.file-max = 65536
kernel.pid_max = 65536
EOF

    sysctl -p >> /dev/null 2>&1
    success "System limits configured"
}

# Configure SSH for security
configure_ssh_security() {
    log "Configuring SSH security..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    # Secure SSH configuration
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
    success "SSH security configured"
}

# Configure firewall basics
configure_firewall_basics() {
    log "Configuring basic firewall..."
    
    case $OS in
        ubuntu|debian)
            ufw --force reset
            ufw allow ssh
            ufw allow 80
            ufw allow 443
            ufw --force enable
            ;;
        centos|rhel|fedora)
            systemctl start firewalld
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --permanent --add-port=80/tcp
            firewall-cmd --permanent --add-port=443/tcp
            firewall-cmd --reload
            ;;
    esac
    success "Basic firewall configured"
}

# Install and configure fail2ban
install_fail2ban() {
    log "Installing and configuring fail2ban..."
    
    case $OS in
        ubuntu|debian)
            apt install -y fail2ban >> /dev/null 2>&1
            ;;
        centos|rhel|fedora)
            yum install -y fail2ban >> /dev/null 2>&1
            ;;
    esac

    # Basic fail2ban configuration
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
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    success "Fail2ban installed and configured"
}

# Verify all installations
verify_installations() {
    log "Verifying all installations..."
    
    local tools=("curl" "wget" "git" "jq" "nginx" "haproxy" "stunnel4" "dropbear" "fail2ban" "certbot")
    
    for tool in "${tools[@]}"; do
        if command -v $tool &> /dev/null || systemctl is-active --quiet $tool 2>/dev/null; then
            success "$tool: ✓ Installed"
        else
            warning "$tool: ✗ Not installed"
        fi
    done
    
    # Check services
    local services=("ssh" "nginx" "haproxy" "fail2ban")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet $service; then
            success "$service: ✓ Running"
        else
            warning "$service: ✗ Not running"
        fi
    done
}

# Create prerequisite report
create_report() {
    log "Creating prerequisite report..."
    
    cat > /tmp/prerequisite_report.txt << EOF
=== dhyntoh VPN Prerequisite Report ===
Generated: $(date)
OS: $OS_NAME
Kernel: $(uname -r)
Architecture: $(uname -m)

=== System Resources ===
RAM: $(free -h | grep Mem: | awk '{print $2}')
Disk: $(df -h / | tail -1 | awk '{print $4}')
CPU: $(nproc) cores

=== Installed Components ===
$(dpkg -l 2>/dev/null | grep -E '^(ii|hi)' | wc -l) packages installed (Debian/Ubuntu)
$(rpm -qa 2>/dev/null | wc -l) packages installed (CentOS/RHEL)

=== Network Status ===
Public IP: $(curl -s4 icanhazip.com)
SSH Status: $(systemctl is-active ssh)
Firewall Status: $(systemctl is-active ufw 2>/dev/null || systemctl is-active firewalld 2>/dev/null || echo "unknown")

=== Next Steps ===
Run the main installer: ./install.sh
Or use quick install: curl -sSL $RAW_URL/quick-install.sh | bash

EOF

    success "Prerequisite report saved: /tmp/prerequisite_report.txt"
}

# Main prerequisite installation
main() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════╗"
    echo "║    dhyntoh VPN Prerequisite Setup   ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    detect_os
    check_system_requirements
    install_base_utilities
    install_development_tools
    install_network_utilities
    install_security_tools
    install_web_servers
    install_database_tools
    install_monitoring_tools
    install_text_tools
    install_compression_tools
    install_version_control
    install_process_management
    install_time_sync
    configure_system_limits
    configure_ssh_security
    configure_firewall_basics
    install_fail2ban
    verify_installations
    create_report
    
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════╗"
    echo "║     PREREQUISITES COMPLETE!         ║"
    echo "╠══════════════════════════════════════╣"
    echo "║ All required components installed   ║"
    echo "║ System optimized and secured        ║"
    echo "║ Ready for VPN installation          ║"
    echo "╚══════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}Next: Run ./install.sh to install the VPN${NC}"
}

main "$@"
