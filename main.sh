#!/bin/bash

# Define colors for better terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
RESET='\033[0m' # No Color
BOLD_GREEN='\033[1;32m' # Bold Green for menu title

# --- Global Paths and Markers ---
# Use readlink -f to get the canonical path of the script, resolving symlinks and /dev/fd/ issues
TRUST_SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$TRUST_SCRIPT_PATH")"
SETUP_MARKER_FILE="/var/lib/trusttunnel/.setup_complete"
TRUST_COMMAND_PATH="/usr/local/bin/trust"

# --- Speed Optimization Functions ---

# Function to apply system-level network optimizations
apply_system_optimizations() {
    echo -e "${CYAN}🚀 Applying system-level speed optimizations...${RESET}"
    
    # Create sysctl optimization file
    cat <<EOF | sudo tee /etc/sysctl.d/99-trusttunnel-optimizations.conf > /dev/null
# TrustTunnel Network Optimizations
# TCP Buffer Sizes
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP Performance
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_adv_win_scale = 1

# Network Core Optimizations
net.core.netdev_max_backlog = 5000
net.core.netdev_budget = 600
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# Memory and CPU
net.ipv4.tcp_mem = 786432 1048576 26777216
net.ipv4.tcp_max_orphans = 819200
vm.swappiness = 10
kernel.numa_balancing = 0
EOF
    
    # Apply optimizations
    sudo sysctl -p /etc/sysctl.d/99-trusttunnel-optimizations.conf > /dev/null 2>&1
    
    # Enable BBR if available
    if lsmod | grep -q tcp_bbr; then
        echo 'net.ipv4.tcp_congestion_control = bbr' | sudo tee -a /etc/sysctl.d/99-trusttunnel-optimizations.conf > /dev/null
        sudo sysctl -w net.ipv4.tcp_congestion_control=bbr > /dev/null 2>&1
    fi
    
    print_success "System optimizations applied successfully!"
}

# Function to optimize network interface
optimize_network_interface() {
    echo -e "${CYAN}🌐 Optimizing network interface...${RESET}"
    
    # Get primary network interface
    local primary_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [ -n "$primary_interface" ]; then
        # Optimize network interface settings
        sudo ethtool -K "$primary_interface" rx on tx on sg on tso on ufo on gso on gro on lro on rxvlan on txvlan on ntuple on rxhash on 2>/dev/null || true
        
        # Set ring buffer sizes
        sudo ethtool -G "$primary_interface" rx 4096 tx 4096 2>/dev/null || true
        
        # Set interrupt coalescing
        sudo ethtool -C "$primary_interface" adaptive-rx on adaptive-tx on rx-usecs 1 tx-usecs 1 2>/dev/null || true
        
        print_success "Network interface optimized: $primary_interface"
    else
        echo -e "${YELLOW}⚠️ Could not detect primary network interface${RESET}"
    fi
}

# Function to create high-performance frp server configuration
create_optimized_server_config() {
    local config_file="$1"
    local listen_port="$2"
    local auth_token="$3"
    
    cat <<EOF > "$config_file"
[common]
# Basic Settings
bind_port = $listen_port
token = $auth_token

# Dashboard
dashboard_port = $((listen_port + 1))
dashboard_user = admin
dashboard_pwd = $auth_token

# Logging
log_file = /var/log/frps.log
log_level = warn
log_max_days = 3

# Performance Optimizations
max_pool_count = 50
max_ports_per_client = 0
subdomain_host = ""
tcp_mux = true
authentication_timeout = 900
heartbeat_timeout = 90
user_conn_timeout = 10

# Advanced Performance
transport.poolCount = 16
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 60
transport.tcpKeepAlive = true
transport.connectServerLocalIP = "0.0.0.0"
transport.proxyProtocolVersion = ""

# Memory and CPU Optimizations
transport.useEncryption = false
transport.useCompression = true
transport.bandwidthLimit = "0"
transport.bandwidthLimitMode = "client"
EOF
}

# Function to create high-performance frp client configuration
create_optimized_client_config() {
    local config_file="$1"
    local server_addr="$2"
    local password="$3"
    local client_name="$4"
    
    local server_host=$(echo "$server_addr" | cut -d':' -f1)
    local server_port=$(echo "$server_addr" | cut -d':' -f2)
    
    cat <<EOF > "$config_file"
[common]
# Server Connection
server_addr = $server_host
server_port = $server_port
token = $password

# Logging
log_file = /var/log/frpc_${client_name}.log
log_level = info
log_max_days = 3

# Performance Optimizations
pool_count = 16
tcp_mux = true
login_fail_exit = true
protocol = tcp
heartbeat_interval = 30
heartbeat_timeout = 90
user = $client_name

# Advanced Performance
transport.poolCount = 16
transport.tcpMux = true
transport.tcpMuxKeepaliveInterval = 60
transport.tcpKeepAlive = true
transport.connectServerLocalIP = "127.0.0.1"
transport.dialServerTimeout = 10
transport.dialServerKeepAlive = 7200
transport.proxyProtocolVersion = ""

# Memory and CPU Optimizations
transport.useEncryption = false
transport.useCompression = true
transport.bandwidthLimit = "0"
transport.bandwidthLimitMode = "client"

# Low-latency optimizations
transport.tcpNoDelay = true
transport.tcpKeepalive = true
transport.dialTimeout = 10

# Connection Optimizations
start = ""
disable_log_color = false
EOF
}

# Function to set process priority and affinity
optimize_process_performance() {
    local service_name="$1"
    
    # Create systemd override directory
    sudo mkdir -p "/etc/systemd/system/${service_name}.service.d"
    
    # Create performance optimization override
    cat <<EOF | sudo tee "/etc/systemd/system/${service_name}.service.d/performance.conf" > /dev/null
[Service]
# Process Priority
Nice=-10
IOSchedulingClass=1
IOSchedulingPriority=4

# CPU Affinity (use all available cores)
CPUAffinity=0-$(nproc --all)

# Memory Optimization
MemoryHigh=1G
MemoryMax=2G
MemorySwapMax=0

# Security with Performance
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log

# Restart Policy
RestartSec=2
StartLimitInterval=0
EOF
    
    # Reload systemd
    sudo systemctl daemon-reload
}

# Function to create performance monitoring script
create_performance_monitor() {
    cat <<'EOF' > /tmp/trusttunnel_monitor.sh
#!/bin/bash
# TrustTunnel Performance Monitor

LOG_FILE="/var/log/trusttunnel_performance.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# System Performance
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
MEM_USAGE=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')
NETWORK_STATS=$(cat /proc/net/dev | grep -E "(eth|ens|enp)" | head -1 | awk '{print "RX: " $2 " TX: " $10}')

# FRP Process Stats
FRP_SERVER_PID=$(pgrep frps)
FRP_CLIENT_PIDS=$(pgrep frpc)

echo "[$DATE] CPU: ${CPU_USAGE}% | MEM: ${MEM_USAGE}% | Network: $NETWORK_STATS" >> "$LOG_FILE"

# Keep log file under 10MB
if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -gt 10485760 ]; then
    tail -n 1000 "$LOG_FILE" > "${LOG_FILE}.tmp"
    mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi
EOF
    
    sudo mv /tmp/trusttunnel_monitor.sh /usr/local/bin/trusttunnel_monitor.sh
    sudo chmod +x /usr/local/bin/trusttunnel_monitor.sh
    
    # Add to cron for monitoring (every 5 minutes) - avoid duplicates
    (crontab -l 2>/dev/null | grep -v "trusttunnel_monitor.sh"; echo "*/5 * * * * /usr/local/bin/trusttunnel_monitor.sh") | crontab -
}

# --- Helper Functions ---

# Function to draw a colored line for menu separation
draw_line() {
  local color="$1"
  local char="$2"
  local length=${3:-40} # Default length 40 if not provided
  printf "${color}"
  for ((i=0; i<length; i++)); do
    printf "$char"
  done
  printf "${RESET}\n"
}

# Function to print success messages in green
print_success() {
  local message="$1"
  echo -e "\033[0;32m✅ $message\033[0m" # Green color for success messages
}

# Function to print error messages in red
print_error() {
  local message="$1"
  echo -e "\033[0;31m❌ $message\033[0m" # Red color for error messages
}

# Function to show service logs and return to a "menu"
show_service_logs() {
  local service_name="$1"
  clear # Clear the screen before showing logs
  echo -e "\033[0;34m--- Displaying logs for $service_name ---\033[0m" # Blue color for header

  # Display the last 50 lines of logs for the specified service
  # --no-pager ensures the output is direct to the terminal without opening 'less'
  sudo journalctl -u "$service_name" -n 50 --no-pager

  echo ""
  echo -e "\033[1;33mPress any key to return to the previous menu...\033[0m" # Yellow color for prompt
  read -n 1 -s -r # Read a single character, silent, raw input

  clear
}

# Function to draw a green line (used for main menu border)
draw_green_line() {
  echo -e "${GREEN}+--------------------------------------------------------+${RESET}"
}

# --- Validation Functions ---

# Function to validate an email address
validate_email() {
  local email="$1"
  if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# Function to generate a random email address
generate_random_email() {
  local random_number=$(( RANDOM * RANDOM ))
  local random_letters=$(tr -dc 'a-z' </dev/urandom | head -c 6)
  echo "example${random_letters}${random_number}@gmail.com"
}

# Function to validate a port number
validate_port() {
  local port="$1"
  if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# Function to validate a domain or IP address
validate_host() {
  local host="$1"
  # Regex for IP address (IPv4)
  local ip_regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
  # Regex for domain name
  local domain_regex="^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"

  if [[ "$host" =~ $ip_regex ]] || [[ "$host" =~ $domain_regex ]]; then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# --- Function to ensure 'trust' command symlink exists ---
ensure_trust_command_available() {
  echo -e "${CYAN}Checking 'trust' command symlink status...${RESET}" # Checking 'trust' command symlink status...

  local symlink_ok=false
  local current_symlink_target=$(readlink "$TRUST_COMMAND_PATH" 2>/dev/null)

  # Check if the current symlink points to a temporary file descriptor
  if [[ "$current_symlink_target" == /dev/fd/* ]]; then
    print_error "❌ Warning: The existing 'trust' symlink points to a temporary location ($current_symlink_target)." # Warning: The existing 'trust' symlink points to a temporary location.
    print_error "   This can happen if the script was run in a non-standard way (e.g., piped to bash)." # This can happen if the script was run in a non-standard way (e.g., piped to bash).
    print_error "   Attempting to fix it by recreating the symlink to the permanent script path." # Attempting to fix it by recreating the symlink to the permanent script path.
  fi

  # Always try to create/update the symlink to the canonical script path
  sudo mkdir -p "$(dirname "$TRUST_COMMAND_PATH")" # Ensure /usr/local/bin exists
  if sudo ln -sf "$TRUST_SCRIPT_PATH" "$TRUST_COMMAND_PATH"; then
    print_success "Attempted to create/update 'trust' command symlink." # Attempted to create/update 'trust' command symlink.
    # Verify immediately after creation
    if [ -L "$TRUST_COMMAND_PATH" ] && [ "$(readlink "$TRUST_COMMAND_PATH" 2>/dev/null)" = "$TRUST_SCRIPT_PATH" ]; then
      symlink_ok=true
    fi
  else
    print_error "Failed to create/update 'trust' command symlink initially. Check permissions." # Failed to create/update 'trust' command symlink initially. Check permissions.
  fi

  if [ "$symlink_ok" = true ]; then
    print_success "'trust' command symlink is correctly set up." # 'trust' command symlink is correctly set up.
    return 0 # Success
  else
    print_error "❌ Critical Error: The 'trust' command symlink is not properly set up or accessible." # Critical Error: The 'trust' command symlink is not properly set up or accessible.
    print_error "   This means the 'trust' command will not work." # This means the 'trust' command will not work.
    print_error "   Please try the following manual steps to fix it:" # Please try the following manual steps to fix it:
    echo -e "${WHITE}   1. Ensure you are running this script directly from its file path (e.g., 'sudo bash /path/to/your_script.sh')." # Ensure you are running this script directly from its file path (e.g., 'sudo bash /path/to/your_script.sh').
    echo -e "${WHITE}   2. Run: sudo ln -sf \"$TRUST_SCRIPT_PATH\" \"$TRUST_COMMAND_PATH\"${RESET}"
    echo -e "${WHITE}   3. Check your PATH: echo \$PATH${RESET}" # Check your PATH: echo $PATH
    echo -e "${WHITE}      Ensure '/usr/local/bin' is in your PATH. If not, add it to your shell's config (e.g., ~/.bashrc, ~/.zshrc):${RESET}" # Ensure '/usr/local/bin' is in your PATH. If not, add it to your shell's config (e.g., ~/.bashrc, ~/.zshrc):
    echo -e "${WHITE}      export PATH=\"/usr/local/bin:\$PATH\"${RESET}"
    echo -e "${WHITE}   4. After making changes, restart your terminal or run: source ~/.bashrc (or your shell's config file)${RESET}" # After making changes, restart your terminal or run: source ~/.bashrc (or your shell's config file)
    sleep 5 # Give user time to read the critical error
    return 1 # Indicate failure
  fi
}

# Function to set process priority and affinity
optimize_process_performance() {
    local service_name="$1"
    
    # Create systemd override directory
    sudo mkdir -p "/etc/systemd/system/${service_name}.service.d"
    
    # Create performance optimization override
    cat <<EOF | sudo tee "/etc/systemd/system/${service_name}.service.d/performance.conf" > /dev/null
[Service]
# Process Priority
Nice=-10
IOSchedulingClass=1
IOSchedulingPriority=4

# CPU Affinity (use all available cores)
CPUAffinity=0-$(nproc --all)

# Memory Optimization
MemoryHigh=1G
MemoryMax=2G
MemorySwapMax=0

# Security with Performance
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log

# Restart Policy
RestartSec=2
StartLimitInterval=0
EOF
    
    # Reload systemd
    sudo systemctl daemon-reload
}

# Function to create performance monitoring script
create_performance_monitor() {
    cat <<'EOF' > /tmp/trusttunnel_monitor.sh
#!/bin/bash
# TrustTunnel Performance Monitor

LOG_FILE="/var/log/trusttunnel_performance.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# System Performance
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
MEM_USAGE=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')
NETWORK_STATS=$(cat /proc/net/dev | grep -E "(eth|ens|enp)" | head -1 | awk '{print "RX: " $2 " TX: " $10}')

# FRP Process Stats
FRP_SERVER_PID=$(pgrep frps)
FRP_CLIENT_PIDS=$(pgrep frpc)

echo "[$DATE] CPU: ${CPU_USAGE}% | MEM: ${MEM_USAGE}% | Network: $NETWORK_STATS" >> "$LOG_FILE"

# Keep log file under 10MB
if [ -f "$LOG_FILE" ] && [ $(stat -c%s "$LOG_FILE") -gt 10485760 ]; then
    tail -n 1000 "$LOG_FILE" > "${LOG_FILE}.tmp"
    mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi
EOF
    
    sudo mv /tmp/trusttunnel_monitor.sh /usr/local/bin/trusttunnel_monitor.sh
    sudo chmod +x /usr/local/bin/trusttunnel_monitor.sh
    
    # Add to cron for monitoring (every 5 minutes)
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/trusttunnel_monitor.sh") | crontab -
}

# Function to show performance status
show_performance_status() {
  clear
  echo ""
    draw_line "$CYAN" "=" 50
    echo -e "${CYAN}        📊 TrustTunnel Performance Status${RESET}"
    draw_line "$CYAN" "=" 50
  echo ""

    # System Info
    echo -e "${GREEN}🖥️  System Information:${RESET}"
    echo -e "  ${WHITE}CPU Cores: ${YELLOW}$(nproc)${RESET}"
    echo -e "  ${WHITE}Memory: ${YELLOW}$(free -h | grep '^Mem:' | awk '{print $2}')${RESET}"
    echo -e "  ${WHITE}Load Average: ${YELLOW}$(uptime | awk -F'load average:' '{print $2}')${RESET}"
    echo ""
    
    # Network Info
    echo -e "${GREEN}🌐 Network Configuration:${RESET}"
    local primary_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -n "$primary_interface" ]; then
        echo -e "  ${WHITE}Primary Interface: ${YELLOW}$primary_interface${RESET}"
        local ip_addr=$(ip addr show "$primary_interface" | grep 'inet ' | awk '{print $2}' | head -n1)
        echo -e "  ${WHITE}IP Address: ${YELLOW}$ip_addr${RESET}"
    fi
    echo ""
    
    # TCP Optimizations Status
    echo -e "${GREEN}⚡ TCP Optimizations:${RESET}"
    local bbr_status=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    echo -e "  ${WHITE}Congestion Control: ${YELLOW}$bbr_status${RESET}"
    local window_scaling=$(sysctl net.ipv4.tcp_window_scaling 2>/dev/null | awk '{print $3}')
    echo -e "  ${WHITE}Window Scaling: ${YELLOW}$window_scaling${RESET}"
    local tcp_timestamps=$(sysctl net.ipv4.tcp_timestamps 2>/dev/null | awk '{print $3}')
    echo -e "  ${WHITE}TCP Timestamps: ${YELLOW}$tcp_timestamps${RESET}"
    echo ""
    
    # FRP Services Status
    echo -e "${GREEN}🔧 FRP Services:${RESET}"
    if systemctl is-active --quiet trusttunnel.service; then
        echo -e "  ${WHITE}Server: ${GREEN}✅ Running${RESET}"
    else
        echo -e "  ${WHITE}Server: ${RED}❌ Not Running${RESET}"
    fi
    
    local client_count=$(systemctl list-units --type=service --state=active | grep -c 'trusttunnel-')
    echo -e "  ${WHITE}Active Clients: ${YELLOW}$client_count${RESET}"
    echo ""
    
    # Performance Monitoring
    echo -e "${GREEN}📈 Performance Monitoring:${RESET}"
    if [ -f "/var/log/trusttunnel_performance.log" ]; then
        echo -e "  ${WHITE}Performance Log: ${GREEN}✅ Active${RESET}"
        echo -e "  ${WHITE}Last Entry: ${YELLOW}$(tail -n1 /var/log/trusttunnel_performance.log)${RESET}"
    else
        echo -e "  ${WHITE}Performance Log: ${RED}❌ Not Found${RESET}"
    fi
    
    echo ""
    echo -e "${YELLOW}Press Enter to return to main menu...${RESET}"
    read -p ""
}

# Function to apply additional optimizations
apply_additional_optimizations() {
    clear
    echo ""
    draw_line "$CYAN" "=" 50
    echo -e "${CYAN}        🚀 Additional Speed Optimizations${RESET}"
    draw_line "$CYAN" "=" 50
    echo ""
    
    echo -e "${CYAN}🔧 Applying advanced optimizations...${RESET}"
    
    # IRQ Balancing
    echo -e "${WHITE}• Setting up IRQ balancing...${RESET}"
    sudo apt-get update > /dev/null 2>&1
    sudo apt-get install -y irqbalance > /dev/null 2>&1
    sudo systemctl enable irqbalance > /dev/null 2>&1
    sudo systemctl start irqbalance > /dev/null 2>&1
    
    # CPU Governor
    echo -e "${WHITE}• Setting CPU governor to performance...${RESET}"
    echo 'performance' | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null 2>&1
    
    # Transparent Huge Pages
    echo -e "${WHITE}• Optimizing memory management...${RESET}"
    echo 'madvise' | sudo tee /sys/kernel/mm/transparent_hugepage/enabled > /dev/null 2>&1
    
    # I/O Scheduler
    echo -e "${WHITE}• Optimizing I/O scheduler...${RESET}"
    for disk in /sys/block/*/queue/scheduler; do
        if [ -f "$disk" ]; then
            echo 'mq-deadline' | sudo tee "$disk" > /dev/null 2>&1
        fi
    done
    
    # Additional Network Optimizations
    echo -e "${WHITE}• Applying additional network optimizations...${RESET}"
    cat <<EOF | sudo tee -a /etc/sysctl.d/99-trusttunnel-optimizations.conf > /dev/null

# Additional Advanced Optimizations
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_retrans_collapse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Memory pressure handling
vm.vfs_cache_pressure = 50
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
EOF
    
    # Apply all optimizations
    sudo sysctl -p /etc/sysctl.d/99-trusttunnel-optimizations.conf > /dev/null 2>&1
    
    print_success "Advanced optimizations applied successfully!"
    echo ""
    echo -e "${GREEN}🎯 Optimizations Applied:${RESET}"
    echo -e "  ${WHITE}• IRQ Balancing${RESET}"
    echo -e "  ${WHITE}• CPU Performance Governor${RESET}"
    echo -e "  ${WHITE}• Memory Management${RESET}"
    echo -e "  ${WHITE}• I/O Scheduler${RESET}"
    echo -e "  ${WHITE}• Advanced Network Stack${RESET}"
    echo -e "  ${WHITE}• TCP FastOpen${RESET}"
    echo -e "  ${WHITE}• BBR Congestion Control${RESET}"
    echo -e "  ${WHITE}• Fair Queuing${RESET}"
    
    echo ""
    echo -e "${YELLOW}Press Enter to return to main menu...${RESET}"
    read -p ""
}

# --- Helper Functions ---

# Function to draw a colored line for menu separation
draw_line() {
  local color="$1"
  local char="$2"
  local length=${3:-40} # Default length 40 if not provided
  printf "${color}"
  for ((i=0; i<length; i++)); do
    printf "$char"
  done
  printf "${RESET}\n"
}

# Function to print success messages in green
print_success() {
  local message="$1"
  echo -e "\033[0;32m✅ $message\033[0m" # Green color for success messages
}

# Function to print error messages in red
print_error() {
  local message="$1"
  echo -e "\033[0;31m❌ $message\033[0m" # Red color for error messages
}

# Function to show service logs and return to a "menu"
show_service_logs() {
  local service_name="$1"
  clear # Clear the screen before showing logs
  echo -e "\033[0;34m--- Displaying logs for $service_name ---\033[0m" # Blue color for header

  # Display the last 50 lines of logs for the specified service
  # --no-pager ensures the output is direct to the terminal without opening 'less'
  sudo journalctl -u "$service_name" -n 50 --no-pager

  echo ""
  echo -e "\033[1;33mPress any key to return to the previous menu...\033[0m" # Yellow color for prompt
  read -n 1 -s -r # Read a single character, silent, raw input

  clear
}

# Function to draw a green line (used for main menu border)
draw_green_line() {
  echo -e "${GREEN}+--------------------------------------------------------+${RESET}"
}

# --- Validation Functions ---

# Function to validate an email address
validate_email() {
  local email="$1"
  if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# Function to generate a random email address
generate_random_email() {
  local random_number=$(( RANDOM * RANDOM ))
  local random_letters=$(tr -dc 'a-z' </dev/urandom | head -c 6)
  echo "example${random_letters}${random_number}@gmail.com"
}

# Function to validate a port number
validate_port() {
  local port="$1"
  if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# Function to validate a domain or IP address
validate_host() {
  local host="$1"
  # Regex for IP address (IPv4)
  local ip_regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
  # Regex for domain name
  local domain_regex="^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"

  if [[ "$host" =~ $ip_regex ]] || [[ "$host" =~ $domain_regex ]]; then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# --- Function to ensure 'trust' command symlink exists ---
ensure_trust_command_available() {
  echo -e "${CYAN}Checking 'trust' command symlink status...${RESET}" # Checking 'trust' command symlink status...

  local symlink_ok=false
  local current_symlink_target=$(readlink "$TRUST_COMMAND_PATH" 2>/dev/null)

  # Check if the current symlink points to a temporary file descriptor
  if [[ "$current_symlink_target" == /dev/fd/* ]]; then
    print_error "❌ Warning: The existing 'trust' symlink points to a temporary location ($current_symlink_target)." # Warning: The existing 'trust' symlink points to a temporary location.
    print_error "   This can happen if the script was run in a non-standard way (e.g., piped to bash)." # This can happen if the script was run in a non-standard way (e.g., piped to bash).
    print_error "   Attempting to fix it by recreating the symlink to the permanent script path." # Attempting to fix it by recreating the symlink to the permanent script path.
  fi

  # Always try to create/update the symlink to the canonical script path
  sudo mkdir -p "$(dirname "$TRUST_COMMAND_PATH")" # Ensure /usr/local/bin exists
  if sudo ln -sf "$TRUST_SCRIPT_PATH" "$TRUST_COMMAND_PATH"; then
    print_success "Attempted to create/update 'trust' command symlink." # Attempted to create/update 'trust' command symlink.
    # Verify immediately after creation
    if [ -L "$TRUST_COMMAND_PATH" ] && [ "$(readlink "$TRUST_COMMAND_PATH" 2>/dev/null)" = "$TRUST_SCRIPT_PATH" ]; then
      symlink_ok=true
    fi
  else
    print_error "Failed to create/update 'trust' command symlink initially. Check permissions." # Failed to create/update 'trust' command symlink initially. Check permissions.
  fi

  if [ "$symlink_ok" = true ]; then
    print_success "'trust' command symlink is correctly set up." # 'trust' command symlink is correctly set up.
    return 0 # Success
  else
    print_error "❌ Critical Error: The 'trust' command symlink is not properly set up or accessible." # Critical Error: The 'trust' command symlink is not properly set up or accessible.
    print_error "   This means the 'trust' command will not work." # This means the 'trust' command will not work.
    print_error "   Please try the following manual steps to fix it:" # Please try the following manual steps to fix it:
    echo -e "${WHITE}   1. Ensure you are running this script directly from its file path (e.g., 'sudo bash /path/to/your_script.sh')." # Ensure you are running this script directly from its file path (e.g., 'sudo bash /path/to/your_script.sh').
    echo -e "${WHITE}   2. Run: sudo ln -sf \"$TRUST_SCRIPT_PATH\" \"$TRUST_COMMAND_PATH\"${RESET}"
    echo -e "${WHITE}   3. Check your PATH: echo \$PATH${RESET}" # Check your PATH: echo $PATH
    echo -e "${WHITE}      Ensure '/usr/local/bin' is in your PATH. If not, add it to your shell's config (e.g., ~/.bashrc, ~/.zshrc):${RESET}" # Ensure '/usr/local/bin' is in your PATH. If not, add it to your shell's config (e.g., ~/.bashrc, ~/.zshrc):
    echo -e "${WHITE}      export PATH=\"/usr/local/bin:\$PATH\"${RESET}"
    echo -e "${WHITE}   4. After making changes, restart your terminal or run: source ~/.bashrc (or your shell's config file)${RESET}" # After making changes, restart your terminal or run: source ~/.bashrc (or your shell's config file)
    sleep 5 # Give user time to read the critical error
    return 1 # Indicate failure
  fi
}

# Function to run network benchmark
run_network_benchmark() {
    clear
    echo ""
    draw_line "$CYAN" "=" 50
    echo -e "${CYAN}        🚀 Network Performance Benchmark${RESET}"
    draw_line "$CYAN" "=" 50
  echo ""

    echo -e "${CYAN}🔍 Running network performance tests...${RESET}"
    echo ""
    
    # Basic Network Info
    echo -e "${GREEN}📡 Network Interface Status:${RESET}"
    local primary_interface=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [ -n "$primary_interface" ]; then
        echo -e "  ${WHITE}Interface: ${YELLOW}$primary_interface${RESET}"
        
        # Get link speed
        local link_speed=$(ethtool "$primary_interface" 2>/dev/null | grep Speed | awk '{print $2}')
        echo -e "  ${WHITE}Link Speed: ${YELLOW}$link_speed${RESET}"
        
        # Get duplex
        local duplex=$(ethtool "$primary_interface" 2>/dev/null | grep Duplex | awk '{print $2}')
        echo -e "  ${WHITE}Duplex: ${YELLOW}$duplex${RESET}"
    fi
    echo ""
    
    # TCP Test
    echo -e "${GREEN}🔧 TCP Configuration Test:${RESET}"
    local tcp_window_size=$(sysctl net.ipv4.tcp_rmem 2>/dev/null | awk '{print $3}')
    echo -e "  ${WHITE}TCP Window Size: ${YELLOW}$tcp_window_size bytes${RESET}"
    
    local congestion_control=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
    echo -e "  ${WHITE}Congestion Control: ${YELLOW}$congestion_control${RESET}"
    
    local bbr_active="❌ No"
    if [ "$congestion_control" = "bbr" ]; then
        bbr_active="✅ Yes"
    fi
    echo -e "  ${WHITE}BBR Active: ${YELLOW}$bbr_active${RESET}"
    echo ""
    
    # Memory Test
    echo -e "${GREEN}💾 Memory Performance:${RESET}"
    local mem_total=$(free -h | grep '^Mem:' | awk '{print $2}')
    local mem_used=$(free -h | grep '^Mem:' | awk '{print $3}')
    local mem_free=$(free -h | grep '^Mem:' | awk '{print $4}')
    echo -e "  ${WHITE}Total Memory: ${YELLOW}$mem_total${RESET}"
    echo -e "  ${WHITE}Used Memory: ${YELLOW}$mem_used${RESET}"
    echo -e "  ${WHITE}Free Memory: ${YELLOW}$mem_free${RESET}"
    echo ""
    
    # CPU Test
    echo -e "${GREEN}🖥️  CPU Performance:${RESET}"
    local cpu_cores=$(nproc)
    echo -e "  ${WHITE}CPU Cores: ${YELLOW}$cpu_cores${RESET}"
    
    local load_1min=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ')
    echo -e "  ${WHITE}Load Average (1min): ${YELLOW}$load_1min${RESET}"
    
    local cpu_freq=$(lscpu | grep "CPU MHz" | awk '{print $3}')
    if [ -n "$cpu_freq" ]; then
        echo -e "  ${WHITE}CPU Frequency: ${YELLOW}$cpu_freq MHz${RESET}"
    fi
    echo ""
    
    # Disk I/O Test
    echo -e "${GREEN}💽 Disk I/O Test:${RESET}"
    echo -e "  ${WHITE}Running disk speed test...${RESET}"
    local disk_write_speed=$(dd if=/dev/zero of=/tmp/disktest bs=1M count=100 2>&1 | grep -oP '\d+\.?\d* MB/s' | tail -1)
    local disk_read_speed=$(dd if=/tmp/disktest of=/dev/null bs=1M count=100 2>&1 | grep -oP '\d+\.?\d* MB/s' | tail -1)
    rm -f /tmp/disktest
    echo -e "  ${WHITE}Write Speed: ${YELLOW}$disk_write_speed${RESET}"
    echo -e "  ${WHITE}Read Speed: ${YELLOW}$disk_read_speed${RESET}"
    echo ""
    
    # Network Latency Test
    echo -e "${GREEN}🌐 Network Latency Test:${RESET}"
    echo -e "  ${WHITE}Testing latency to common servers...${RESET}"
    
    # Test to Google DNS
    local google_latency=$(ping -c 3 8.8.8.8 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
    if [ -n "$google_latency" ]; then
        echo -e "  ${WHITE}Google DNS (8.8.8.8): ${YELLOW}${google_latency}ms${RESET}"
    else
        echo -e "  ${WHITE}Google DNS (8.8.8.8): ${RED}Failed${RESET}"
    fi
    
    # Test to Cloudflare DNS
    local cloudflare_latency=$(ping -c 3 1.1.1.1 2>/dev/null | tail -1 | awk -F'/' '{print $5}')
    if [ -n "$cloudflare_latency" ]; then
        echo -e "  ${WHITE}Cloudflare DNS (1.1.1.1): ${YELLOW}${cloudflare_latency}ms${RESET}"
    else
        echo -e "  ${WHITE}Cloudflare DNS (1.1.1.1): ${RED}Failed${RESET}"
    fi
    echo ""
    
    # Performance Score
    echo -e "${GREEN}📊 Performance Score:${RESET}"
    local score=0
    
    # BBR check
    if [ "$congestion_control" = "bbr" ]; then
        score=$((score + 25))
    fi
    
    # Memory check
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    if [ "$mem_usage" -lt 80 ]; then
        score=$((score + 25))
    fi
    
    # CPU check
    local load_numeric=$(echo "$load_1min" | cut -d'.' -f1)
    if [ "$load_numeric" -lt "$cpu_cores" ]; then
        score=$((score + 25))
    fi
    
    # Network check
    if [ -n "$google_latency" ]; then
        score=$((score + 25))
    fi
    
    local performance_rating=""
    if [ "$score" -ge 90 ]; then
        performance_rating="${GREEN}Excellent 🚀${RESET}"
    elif [ "$score" -ge 70 ]; then
        performance_rating="${YELLOW}Good 👍${RESET}"
    elif [ "$score" -ge 50 ]; then
        performance_rating="${YELLOW}Fair 📊${RESET}"
    else
        performance_rating="${RED}Needs Improvement ⚠️${RESET}"
    fi
    
    echo -e "  ${WHITE}Score: ${YELLOW}$score/100${RESET}"
    echo -e "  ${WHITE}Rating: $performance_rating"
    echo ""
    
    echo -e "${YELLOW}Press Enter to return to main menu...${RESET}"
    read -p ""
}

# Function to print error messages in red
print_error() {
  local message="$1"
  echo -e "\033[0;31m❌ $message\033[0m" # Red color for error messages
}

# Function to show service logs and return to a "menu"
show_service_logs() {
  local service_name="$1"
  clear # Clear the screen before showing logs
  echo -e "\033[0;34m--- Displaying logs for $service_name ---\033[0m" # Blue color for header

  # Display the last 50 lines of logs for the specified service
  # --no-pager ensures the output is direct to the terminal without opening 'less'
  sudo journalctl -u "$service_name" -n 50 --no-pager

  echo ""
  echo -e "\033[1;33mPress any key to return to the previous menu...\033[0m" # Yellow color for prompt
  read -n 1 -s -r # Read a single character, silent, raw input

  clear
}

# Function to draw a green line (used for main menu border)
draw_green_line() {
  echo -e "${GREEN}+--------------------------------------------------------+${RESET}"
}

# --- Validation Functions ---

# Function to validate an email address
validate_email() {
  local email="$1"
  if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]]; then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# Function to generate a random email address
generate_random_email() {
  local random_number=$(( RANDOM * RANDOM ))
  local random_letters=$(tr -dc 'a-z' </dev/urandom | head -c 6)
  echo "example${random_letters}${random_number}@gmail.com"
}

# Function to validate a port number
validate_port() {
  local port="$1"
  if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# Function to validate a domain or IP address
validate_host() {
  local host="$1"
  # Regex for IP address (IPv4)
  local ip_regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
  # Regex for domain name
  local domain_regex="^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"

  if [[ "$host" =~ $ip_regex ]] || [[ "$host" =~ $domain_regex ]]; then
    return 0 # Valid
  else
    return 1 # Invalid
  fi
}

# --- Function to ensure 'trust' command symlink exists ---
ensure_trust_command_available() {
  echo -e "${CYAN}Checking 'trust' command symlink status...${RESET}" # Checking 'trust' command symlink status...

  local symlink_ok=false
  local current_symlink_target=$(readlink "$TRUST_COMMAND_PATH" 2>/dev/null)

  # Check if the current symlink points to a temporary file descriptor
  if [[ "$current_symlink_target" == /dev/fd/* ]]; then
    print_error "❌ Warning: The existing 'trust' symlink points to a temporary location ($current_symlink_target)." # Warning: The existing 'trust' symlink points to a temporary location.
    print_error "   This can happen if the script was run in a non-standard way (e.g., piped to bash)." # This can happen if the script was run in a non-standard way (e.g., piped to bash).
    print_error "   Attempting to fix it by recreating the symlink to the permanent script path." # Attempting to fix it by recreating the symlink to the permanent script path.
  fi

  # Always try to create/update the symlink to the canonical script path
  sudo mkdir -p "$(dirname "$TRUST_COMMAND_PATH")" # Ensure /usr/local/bin exists
  if sudo ln -sf "$TRUST_SCRIPT_PATH" "$TRUST_COMMAND_PATH"; then
    print_success "Attempted to create/update 'trust' command symlink." # Attempted to create/update 'trust' command symlink.
    # Verify immediately after creation
    if [ -L "$TRUST_COMMAND_PATH" ] && [ "$(readlink "$TRUST_COMMAND_PATH" 2>/dev/null)" = "$TRUST_SCRIPT_PATH" ]; then
      symlink_ok=true
    fi
  else
    print_error "Failed to create/update 'trust' command symlink initially. Check permissions." # Failed to create/update 'trust' command symlink initially. Check permissions.
  fi

  if [ "$symlink_ok" = true ]; then
    print_success "'trust' command symlink is correctly set up." # 'trust' command symlink is correctly set up.
    return 0 # Success
  else
    print_error "❌ Critical Error: The 'trust' command symlink is not properly set up or accessible." # Critical Error: The 'trust' command symlink is not properly set up or accessible.
    print_error "   This means the 'trust' command will not work." # This means the 'trust' command will not work.
    print_error "   Please try the following manual steps to fix it:" # Please try the following manual steps to fix it:
    echo -e "${WHITE}   1. Ensure you are running this script directly from its file path (e.g., 'sudo bash /path/to/your_script.sh')." # Ensure you are running this script directly from its file path (e.g., 'sudo bash /path/to/your_script.sh').
    echo -e "${WHITE}   2. Run: sudo ln -sf \"$TRUST_SCRIPT_PATH\" \"$TRUST_COMMAND_PATH\"${RESET}"
    echo -e "${WHITE}   3. Check your PATH: echo \$PATH${RESET}" # Check your PATH: echo $PATH
    echo -e "${WHITE}      Ensure '/usr/local/bin' is in your PATH. If not, add it to your shell's config (e.g., ~/.bashrc, ~/.zshrc):${RESET}" # Ensure '/usr/local/bin' is in your PATH. If not, add it to your shell's config (e.g., ~/.bashrc, ~/.zshrc):
    echo -e "${WHITE}      export PATH=\"/usr/local/bin:\$PATH\"${RESET}"
    echo -e "${WHITE}   4. After making changes, restart your terminal or run: source ~/.bashrc (or your shell's config file)${RESET}" # After making changes, restart your terminal or run: source ~/.bashrc (or your shell's config file)
    sleep 5 # Give user time to read the critical error
    return 1 # Indicate failure
  fi
}

# Function to schedule cron job for service restarts
schedule_cron_job_action() {
  clear
  echo ""
  draw_line "$CYAN" "=" 40
  echo -e "${CYAN}        📅 Schedule Service Restart${RESET}"
  draw_line "$CYAN" "=" 40
  echo ""
  
  # Get list of active services
  mapfile -t active_services < <(sudo systemctl list-units --type=service --state=active --plain --no-legend | grep -E "(client|server)" | awk '{print $1}' | sort)
  
  if [ ${#active_services[@]} -eq 0 ]; then
    print_error "No active services found to schedule restarts for."
  echo ""
    echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}"
    read -p ""
    return 1
  fi
  
  echo -e "${CYAN}Available services to schedule restarts for:${RESET}"
  for i in "${!active_services[@]}"; do
    echo -e "${WHITE}  $((i+1)). ${active_services[i]}${RESET}"
  done
  echo ""
  
  read -p "Enter service number: " service_choice
  
  if ! [[ "$service_choice" =~ ^[0-9]+$ ]] || [ "$service_choice" -lt 1 ] || [ "$service_choice" -gt "${#active_services[@]}" ]; then
    print_error "Invalid service selection."
  echo ""
    echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}"
    read -p ""
    return 1
  fi
  
  local service_to_restart="${active_services[$((service_choice-1))]}"
  
  echo ""
  echo -e "${CYAN}Select restart interval:${RESET}"
  echo -e "${WHITE}  1. Every 30 minutes${RESET}"
  echo -e "${WHITE}  2. Every hour${RESET}"
  echo -e "${WHITE}  3. Every 2 hours${RESET}"
  echo -e "${WHITE}  4. Every 4 hours${RESET}"
  echo -e "${WHITE}  5. Every 6 hours${RESET}"
  echo -e "${WHITE}  6. Every 12 hours${RESET}"
  echo -e "${WHITE}  7. Every 24 hours${RESET}"
  echo ""
  read -p "Enter your choice (1-7): " choice

  case "$choice" in
    1)
      minutes_from_now=30
      description="30 minutes"
      ;;
    2)
      minutes_from_now=60
      description="1 hour"
      ;;
    3)
      minutes_from_now=120
      description="2 hours"
      ;;
    4)
      minutes_from_now=240
      description="4 hours"
      ;;
    5)
      minutes_from_now=360
      description="6 hours"
      ;;
    6)
      minutes_from_now=720
      description="12 hours"
      ;;
    7)
      minutes_from_now=1440
      description="24 hours"
      ;;
    *)
      print_error "Invalid choice. No cron job will be scheduled." # Invalid choice. No cron job will be scheduled.
      echo ""
      echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
      read -p ""
      return 1 # Indicate failure
      ;;
  esac

  echo -e "${CYAN}Scheduling '$service_to_restart' to restart every $description...${RESET}" # Scheduling 'service_to_restart' to restart every description...

  # Create recurring cron job patterns based on the chosen interval
  local cron_schedule=""
  case "$choice" in
    1)
      cron_schedule="*/30 * * * *" # Every 30 minutes
      ;;
    2)
      cron_schedule="0 * * * *" # Every hour (at minute 0)
      ;;
    3)
      cron_schedule="0 */2 * * *" # Every 2 hours (at minute 0)
      ;;
    4)
      cron_schedule="0 */4 * * *" # Every 4 hours (at minute 0)
      ;;
    5)
      cron_schedule="0 */6 * * *" # Every 6 hours (at minute 0)
      ;;
    6)
      cron_schedule="0 */12 * * *" # Every 12 hours (at minute 0)
      ;;
    7)
      cron_schedule="0 0 * * *" # Every day at midnight
      ;;
  esac

  # Define the cron command
  # Using an absolute path for systemctl is good practice in cron jobs
  local cron_command="/usr/bin/systemctl restart $service_to_restart >> /var/log/trusttunnel_cron.log 2>&1"
  local cron_job_entry="$cron_schedule $cron_command # TrustTunnel automated restart for $service_to_restart"

  # --- Start of improved cron job management ---
  local temp_cron_file=$(mktemp)
  if ! sudo crontab -l &> /dev/null; then
      # If crontab is empty or doesn't exist, create an empty one
      echo "" | sudo crontab -
  fi
  sudo crontab -l > "$temp_cron_file"

  # Remove any existing TrustTunnel cron job for this service
  sed -i "/# TrustTunnel automated restart for $service_to_restart$/d" "$temp_cron_file"

  # Add the new cron job entry
  echo "$cron_job_entry" >> "$temp_cron_file"

  # Load the modified crontab
  if sudo crontab "$temp_cron_file"; then
    print_success "Successfully scheduled a restart for '$service_to_restart' every $description." # Successfully scheduled a restart for 'service_to_restart' every description.
    echo -e "${CYAN}   The cron job entry looks like this:${RESET}" # The cron job entry looks like this:
    echo -e "${WHITE}   $cron_job_entry${RESET}"
    echo -e "${CYAN}   You can check scheduled cron jobs with: ${WHITE}sudo crontab -l${RESET}" # You can check scheduled cron jobs with: sudo crontab -l
    echo -e "${CYAN}   Logs will be written to: ${WHITE}/var/log/trusttunnel_cron.log${RESET}" # Logs will be written to: /var/log/trusttunnel_cron.log
  else
    print_error "Failed to schedule the cron job. Check permissions or cron service status." # Failed to schedule the cron job. Check permissions or cron service status.
  fi

  # Clean up the temporary file
  rm -f "$temp_cron_file"
  # --- End of improved cron job management ---

  echo ""
  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
  read -p ""
}

# --- New: delete_cron_job_action to remove scheduled restarts ---
delete_cron_job_action() {
  clear
  echo ""
  draw_line "$RED" "=" 40
  echo -e "${RED}        🗑️ Delete Scheduled Restart (Cron)${RESET}" # Delete Scheduled Restart (Cron)
  draw_line "$RED" "=" 40
  echo ""

  echo -e "${CYAN}🔍 Searching for TrustTunnel related services with scheduled restarts...${RESET}" # Searching for TrustTunnel related services with scheduled restarts...

  # List active TrustTunnel related services (both server and clients)
  mapfile -t services_with_cron < <(sudo crontab -l 2>/dev/null | grep "# TrustTunnel automated restart for" | awk '{print $NF}' | sort -u)

  # Extract service names from the cron job comments
  local service_names=()
  for service_comment in "${services_with_cron[@]}"; do
    # The service name is the last word in the comment, which is the service name itself
    # We need to strip the "# TrustTunnel automated restart for " part
    local extracted_name=$(echo "$service_comment" | sed 's/# TrustTunnel automated restart for //')
    service_names+=("$extracted_name")
  done

  if [ ${#service_names[@]} -eq 0 ]; then
    print_error "No TrustTunnel services with scheduled cron jobs found." # No TrustTunnel services with scheduled cron jobs found.
    echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
    read -p ""
    return 1
  fi

  echo -e "${CYAN}📋 Please select a service to delete its scheduled restart:${RESET}" # Please select a service to delete its scheduled restart:
  # Add a "Back to previous menu" option
  service_names+=("Back to previous menu")
  select selected_service_name in "${service_names[@]}"; do
    if [[ "$selected_service_name" == "Back to previous menu" ]]; then
      echo -e "${YELLOW}Returning to previous menu...${RESET}" # Returning to previous menu...
      echo ""
      return 0
    elif [ -n "$selected_service_name" ]; then
      break # Exit the select loop if a valid option is chosen
    else
      print_error "Invalid selection. Please enter a valid number." # Invalid selection. Please enter a valid number.
    fi
  done
  echo ""

  if [[ -z "$selected_service_name" ]]; then
    print_error "No service selected. Aborting." # No service selected. Aborting.
    echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
    read -p ""
    return 1
  fi

  echo -e "${CYAN}Attempting to delete cron job for '$selected_service_name'...${RESET}" # Attempting to delete cron job for 'selected_service_name'...

  # --- Start of improved cron job management for deletion ---
  local temp_cron_file=$(mktemp)
  if ! sudo crontab -l &> /dev/null; then
      # If crontab is empty or doesn't exist, nothing to delete
      print_error "Crontab is empty or not accessible. Nothing to delete." # Crontab is empty or not accessible. Nothing to delete.
      rm -f "$temp_cron_file"
      echo ""
      echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
      read -p ""
      return 1
  fi
  sudo crontab -l > "$temp_cron_file"

  # Remove the cron job for the selected service using the unique identifier
  sed -i "/# TrustTunnel automated restart for $selected_service_name$/d" "$temp_cron_file"

  # Load the modified crontab
  if sudo crontab "$temp_cron_file"; then
    print_success "Successfully removed scheduled restart for '$selected_service_name'." # Successfully removed scheduled restart for 'selected_service_name'.
    echo -e "${WHITE}You can verify with: ${YELLOW}sudo crontab -l${RESET}" # You can verify with: sudo crontab -l
  else
    print_error "Failed to delete cron job. It might not exist or there's a permission issue." # Failed to delete cron job. It might not exist or there's a permission issue.
  fi

  # Clean up the temporary file
  rm -f "$temp_cron_file"
  # --- End of improved cron job management ---

  echo ""
  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
  read -p ""
}

# --- Uninstall TrustTunnel Action ---
uninstall_trusttunnel_action() {
  clear
  echo ""
  echo -e "${RED}⚠️ Are you sure you want to uninstall TrustTunnel and remove all associated files and services? (y/N): ${RESET}" # Are you sure you want to uninstall TrustTunnel and remove all associated files and services? (y/N):
  read -p "" confirm
  echo ""

  if [[ "$confirm" =~ ^[Yy]$ ]]; then
    echo "🧹 Uninstalling TrustTunnel..." # Uninstalling TrustTunnel...

    # --- Explicitly handle trusttunnel.service (server) ---
    local server_service_name="trusttunnel.service"
    if systemctl list-unit-files --full --no-pager | grep -q "^$server_service_name"; then
      echo "🛑 Stopping and disabling TrustTunnel server service ($server_service_name)..." # Stopping and disabling TrustTunnel server service (server_service_name)...
      sudo systemctl stop "$server_service_name" > /dev/null 2>&1
      sudo systemctl disable "$server_service_name" > /dev/null 2>&1
      sudo rm -f "/etc/systemd/system/$server_service_name" > /dev/null 2>&1
      print_success "TrustTunnel server service removed." # TrustTunnel server service removed.
    else
      echo "⚠️ TrustTunnel server service ($server_service_name) not found. Skipping." # TrustTunnel server service (server_service_name) not found. Skipping.
    fi

    # Find and remove all trusttunnel-* services (clients)
    echo "Searching for TrustTunnel client services to remove..." # Searching for TrustTunnel client services to remove...
    # List all unit files that start with 'trusttunnel-'
    mapfile -t trusttunnel_client_services < <(sudo systemctl list-unit-files --full --no-pager | grep '^trusttunnel-.*\.service' | awk '{print $1}')

    if [ ${#trusttunnel_client_services[@]} -gt 0 ]; then
      echo "🛑 Stopping and disabling TrustTunnel client services..." # Stopping and disabling TrustTunnel client services...
      for service_file in "${trusttunnel_client_services[@]}"; do
        local service_name=$(basename "$service_file") # Get just the service name from the file path
        echo "  - Processing $service_name..." # Processing service_name...
        sudo systemctl stop "$service_name" > /dev/null 2>&1
        sudo systemctl disable "$service_name" > /dev/null 2>&1
        sudo rm -f "/etc/systemd/system/$service_name" > /dev/null 2>&1
      done
      print_success "All TrustTunnel client services have been stopped, disabled, and removed." # All TrustTunnel client services have been stopped, disabled, and removed.
    else
      echo "⚠️ No TrustTunnel client services found to remove." # No TrustTunnel client services found to remove.
    fi

    sudo systemctl daemon-reload # Reload daemon after removing services

    # Remove rstun folder if exists
    if [ -d "rstun" ]; then
      echo "🗑️ Removing 'rstun' folder..." # Removing 'rstun' folder...
      rm -rf rstun
      print_success "'rstun' folder removed successfully." # 'rstun' folder removed successfully.
    else
      echo "⚠️ 'rstun' folder not found." # 'rstun' folder not found.
    fi

    # Remove TrustTunnel related cron jobs
    echo -e "${CYAN}🧹 Removing any associated TrustTunnel cron jobs...${RESET}" # Removing any associated TrustTunnel cron jobs...
    (sudo crontab -l 2>/dev/null | grep -v "# TrustTunnel automated restart for") | sudo crontab -
    print_success "Associated cron jobs removed." # Associated cron jobs removed.

    # Remove 'trust' command symlink
    if [ -L "$TRUST_COMMAND_PATH" ]; then # Check if it's a symbolic link
      echo "🗑️ Removing 'trust' command symlink..." # Removing 'trust' command symlink...
      sudo rm -f "$TRUST_COMMAND_PATH"
      print_success "'trust' command symlink removed." # 'trust' command symlink removed.
    fi
    # Remove setup marker file
    if [ -f "$SETUP_MARKER_FILE" ]; then
      echo "🗑️ Removing setup marker file..." # Removing setup marker file...
      sudo rm -f "$SETUP_MARKER_FILE"
      print_success "Setup marker file removed." # Setup marker file removed.
    fi

    print_success "TrustTunnel uninstallation complete." # TrustTunnel uninstallation complete.
  else
    echo -e "${YELLOW}❌ Uninstall cancelled.${RESET}" # Uninstall cancelled.
  fi
  echo ""
  echo -e "${YELLOW}Press Enter to return to main menu...${RESET}" # Press Enter to return to main menu...
  read -p ""
}

# --- Install TrustTunnel Action ---
install_trusttunnel_action() {
  clear
  echo ""
  draw_line "$CYAN" "=" 40
  echo -e "${CYAN}        📥 Installing TrustTunnel${RESET}" # Installing TrustTunnel
  draw_line "$CYAN" "=" 40
  echo ""

  # Delete existing rstun folder if it exists
  if [ -d "rstun" ]; then
    echo -e "${YELLOW}🧹 Removing existing 'rstun' folder...${RESET}" # Removing existing 'rstun' folder...
    rm -rf rstun
    print_success "Existing 'rstun' folder removed." # Existing 'rstun' folder removed.
  fi

  echo -e "${CYAN}🚀 Detecting system architecture...${RESET}" # Detecting system architecture...
  local arch=$(uname -m)
  local download_url=""
  local filename=""
  local supported_arch=true # Flag to track if architecture is directly supported

  case "$arch" in
    "x86_64")
      filename="frp_0.52.3_linux_amd64.tar.gz"
      ;;
    "aarch64" | "arm64")
      filename="frp_0.52.3_linux_arm64.tar.gz"
      ;;
    "armv7l")
      filename="frp_0.52.3_linux_arm.tar.gz"
      ;;
    *)
      supported_arch=false # Mark as unsupported
      echo -e "${RED}❌ Error: Unsupported architecture detected: $arch${RESET}" # Error: Unsupported architecture detected: arch
      echo -e "${YELLOW}Do you want to try installing the x86_64 version as a fallback? (y/N): ${RESET}" # Do you want to try installing the x86_64 version as a fallback? (y/N):
      read -p "" fallback_confirm
      echo ""
      if [[ "$fallback_confirm" =~ ^[Yy]$ ]]; then
        filename="frp_0.52.3_linux_amd64.tar.gz"
        echo -e "${CYAN}Proceeding with x86_64 version as requested.${RESET}" # Proceeding with x86_64 version as requested.
      else
        echo -e "${YELLOW}Installation cancelled. Please download frp manually for your system from https://github.com/fatedier/frp/releases${RESET}" # Installation cancelled. Please download frp manually for your system from https://github.com/fatedier/frp/releases
        echo ""
        echo -e "${YELLOW}Press Enter to return to main menu...${RESET}" # Press Enter to return to main menu...
        read -p ""
        return 1 # Indicate failure
      fi
      ;;
  esac

  download_url="https://github.com/fatedier/frp/releases/download/v0.52.3/${filename}"

  echo -e "${CYAN}Downloading $filename for $arch...${RESET}" # Downloading filename for arch...
  if wget -q --show-progress "$download_url" -O "$filename"; then
    print_success "Download complete!" # Download complete!
  else
    echo -e "${RED}❌ Error: Failed to download $filename. Please check your internet connection or the URL.${RESET}" # Error: Failed to download filename. Please check your internet connection or the URL.
    echo ""
    echo -e "${YELLOW}Press Enter to return to main menu...${RESET}" # Press Enter to return to main menu...
    read -p ""
    return 1 # Indicate failure
  fi

  echo -e "${CYAN}📦 Extracting files...${RESET}" # Extracting files...
  if tar -xzf "$filename"; then
    mv "${filename%.tar.gz}" rstun # Rename extracted folder to 'rstun' for compatibility
    print_success "Extraction complete!" # Extraction complete!
  else
    echo -e "${RED}❌ Error: Failed to extract $filename. Corrupted download?${RESET}" # Error: Failed to extract filename. Corrupted download?
    echo ""
    echo -e "${YELLOW}Press Enter to return to main menu...${RESET}" # Press Enter to return to main menu...
    read -p ""
    return 1 # Indicate failure
  fi

  echo -e "${CYAN}➕ Setting execute permissions...${RESET}" # Setting execute permissions...
  find rstun -type f -exec chmod +x {} \;
  print_success "Permissions set." # Permissions set.

  echo -e "${CYAN}🗑️ Cleaning up downloaded archive...${RESET}" # Cleaning up downloaded archive...
  rm "$filename"
  print_success "Cleanup complete." # Cleanup complete.

  echo ""
  print_success "TrustTunnel installation complete!" # TrustTunnel installation complete!
  # Ensure the 'trust' command is available after installation
  ensure_trust_command_available # Call the new function here
  
  # Apply initial system optimizations
  echo -e "${CYAN}🚀 Applying system optimizations for better performance...${RESET}"
  apply_system_optimizations
  optimize_network_interface
  
  echo ""
  echo -e "${GREEN}🎯 System Ready for High-Performance Tunneling!${RESET}"
  echo -e "  ${WHITE}• System optimizations applied${RESET}"
  echo -e "  ${WHITE}• Network interface optimized${RESET}"
  echo -e "  ${WHITE}• Ready for tunnel creation${RESET}"
  
  echo ""
  echo -e "${YELLOW}Press Enter to return to main menu...${RESET}" # Press Enter to return to main menu...
  read -p ""
}

# --- Add New Server Action (Beautified) ---
add_new_server_action() {
  clear
  echo ""
  draw_line "$CYAN" "=" 40
  echo -e "${CYAN}        ➕ Add New TrustTunnel Server${RESET}" # Add New TrustTunnel Server
  draw_line "$CYAN" "=" 40
  echo ""

  if [ ! -f "rstun/frps" ]; then
    echo -e "${RED}❗ Server build (frps) not found.${RESET}" # Server build (frps) not found.
    echo -e "${YELLOW}Please run 'Install TrustTunnel' option from the main menu first.${RESET}" # Please run 'Install TrustTunnel' option from the main menu first.
    echo ""
    echo -e "${YELLOW}Press Enter to return to main menu...${RESET}" # Press Enter to return to main menu...
    read -p ""
    return # Use return instead of continue in a function
  fi

    echo -e "${CYAN}⚙️ Server Configuration:${RESET}" # Server Configuration:
  echo -e "  (Using efficient TCP multiplexing - no SSL needed)"
  echo -e "  (Default server port is 7000)"
    
    # Validate Listen Port
    local listen_port
    while true; do
    echo -e "👉 ${WHITE}Enter server port (1-65535, default 7000):${RESET} " # Enter server port (1-65535, default 7000):
      read -p "" listen_port_input
    listen_port=${listen_port_input:-7000} # Apply default if empty
      if validate_port "$listen_port"; then
        break
      else
        print_error "Invalid port number. Please enter a number between 1 and 65535." # Invalid port number. Please enter a number between 1 and 65535.
      fi
    done

  echo -e "👉 ${WHITE}Enter authentication token:${RESET} " # Enter authentication token:
  read -p "" auth_token
    echo ""

  if [[ -z "$auth_token" ]]; then
    echo -e "${RED}❌ Authentication token cannot be empty!${RESET}" # Authentication token cannot be empty!
      echo ""
      echo -e "${YELLOW}Press Enter to return to main menu...${RESET}" # Press Enter to return to main menu...
      read -p ""
      return # Use return instead of exit 1
    fi

    local service_file="/etc/systemd/system/trusttunnel.service"
  local config_file="$(pwd)/rstun/frps.ini"

    if systemctl is-active --quiet trusttunnel.service || systemctl is-enabled --quiet trusttunnel.service; then
      echo -e "${YELLOW}🛑 Stopping existing Trusttunnel service...${RESET}" # Stopping existing Trusttunnel service...
      sudo systemctl stop trusttunnel.service > /dev/null 2>&1
      echo -e "${YELLOW}🗑️ Disabling and removing existing Trusttunnel service...${RESET}" # Disabling and removing existing Trusttunnel service...
      sudo systemctl disable trusttunnel.service > /dev/null 2>&1
      sudo rm -f /etc/systemd/system/trusttunnel.service > /dev/null 2>&1
      sudo systemctl daemon-reload > /dev/null 2>&1
      print_success "Existing TrustTunnel service removed." # Existing TrustTunnel service removed.
    fi

  # Remove old configuration files
  rm -f "$(pwd)/rstun/"*.ini > /dev/null 2>&1
  
  # Create optimized frps configuration file
  create_optimized_server_config "$config_file" "$listen_port" "$auth_token"

  # Create systemd service file
    cat <<EOF | sudo tee "$service_file" > /dev/null
[Unit]
Description=TrustTunnel FRP Server
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=$(pwd)/rstun/frps -c $(pwd)/rstun/frps.ini
Restart=always
RestartSec=2
User=$(whoami)

[Install]
WantedBy=multi-user.target
EOF

    echo -e "${CYAN}🔧 Reloading systemd daemon...${RESET}" # Reloading systemd daemon...
    sudo systemctl daemon-reload

    echo -e "${CYAN}🚀 Enabling and starting Trusttunnel service...${RESET}" # Enabling and starting Trusttunnel service...
    sudo systemctl enable trusttunnel.service > /dev/null 2>&1
  
  # Apply system optimizations
  apply_system_optimizations
  optimize_network_interface
  optimize_process_performance "trusttunnel"
  create_performance_monitor
  
    sudo systemctl start trusttunnel.service > /dev/null 2>&1

  print_success "TrustTunnel server started with maximum performance optimizations!" # TrustTunnel server started successfully!
  echo -e "${GREEN}📊 Server Info:${RESET}"
  echo -e "  ${WHITE}Server Port: ${YELLOW}$listen_port${RESET}"
  echo -e "  ${WHITE}Dashboard: ${YELLOW}http://YOUR_SERVER_IP:$((listen_port + 1))${RESET}"
  echo -e "  ${WHITE}Auth Token: ${YELLOW}$auth_token${RESET}"
  echo ""
  echo -e "${GREEN}🚀 Applied Optimizations:${RESET}"
  echo -e "  ${WHITE}• BBR Congestion Control${RESET}"
  echo -e "  ${WHITE}• TCP Window Scaling${RESET}"
  echo -e "  ${WHITE}• Network Buffer Optimization${RESET}"
  echo -e "  ${WHITE}• Process Priority Enhancement${RESET}"
  echo -e "  ${WHITE}• Memory Management Tuning${RESET}"
  echo -e "  ${WHITE}• Connection Pooling (16 pools)${RESET}"
  echo -e "  ${WHITE}• TCP Multiplexing${RESET}"
  echo -e "  ${WHITE}• Performance Monitoring${RESET}"

  echo ""
  echo -e "${YELLOW}Do you want to view the logs for trusttunnel.service now? (y/N): ${RESET}" # Do you want to view the logs for trusttunnel.service now? (y/N):
  read -p "" view_logs_choice
  echo ""

  if [[ "$view_logs_choice" =~ ^[Yy]$ ]]; then
    show_service_logs trusttunnel.service
  fi

  echo ""
  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
  read -p ""
}

# Function to parse port ranges and lists
parse_ports() {
  local input="$1"
  local -n result_array=$2
  
  # Clear the result array
  result_array=()
  
  # Remove all spaces from input
  input=$(echo "$input" | tr -d ' ')
  
  # Split by comma
  IFS=',' read -ra parts <<< "$input"
  
  for part in "${parts[@]}"; do
    if [[ "$part" =~ ^[0-9]+-[0-9]+$ ]]; then
      # This is a range (e.g., 1000-1300)
      local start_port=$(echo "$part" | cut -d'-' -f1)
      local end_port=$(echo "$part" | cut -d'-' -f2)
      
      # Validate range
      if ! validate_port "$start_port" || ! validate_port "$end_port"; then
        print_error "Invalid port range: $part"
        return 1
      fi
      
      if (( start_port > end_port )); then
        print_error "Invalid range: start port ($start_port) must be less than or equal to end port ($end_port)"
        return 1
      fi
      
      # Add all ports in the range
      for ((port=start_port; port<=end_port; port++)); do
        result_array+=("$port")
      done
      
    elif [[ "$part" =~ ^[0-9]+$ ]]; then
      # This is a single port
      if validate_port "$part"; then
        result_array+=("$part")
      else
        print_error "Invalid port: $part"
        return 1
      fi
    else
      # Invalid format
      print_error "Invalid format: $part"
      return 1
    fi
  done
  
  # Check if we have any ports
  if [ ${#result_array[@]} -eq 0 ]; then
    return 1
  fi
  
  # Remove duplicates and sort
  IFS=$'\n' result_array=($(printf '%s\n' "${result_array[@]}" | sort -n | uniq))
  
  return 0
}

add_new_client_action() {
  clear
  echo ""
  draw_line "$CYAN" "=" 40
  echo -e "${CYAN}        ➕ Add New TrustTunnel Client${RESET}" # Add New TrustTunnel Client
  draw_line "$CYAN" "=" 40
  echo ""

  # Prompt for the client name (e.g., asiatech, respina, server2)
  echo -e "👉 ${WHITE}Enter client name (e.g., asiatech, respina, server2):${RESET} " # Enter client name (e.g., asiatech, respina, server2):
  read -p "" client_name
  echo ""

  # Construct the service name based on the client name
  service_name="trusttunnel-$client_name"
  # Define the path for the systemd service file
  service_file="/etc/systemd/system/${service_name}.service"

  # Check if a service with the given name already exists
  if [ -f "$service_file" ]; then
    echo -e "${RED}❌ Service with this name already exists.${RESET}" # Service with this name already exists.
    echo ""
    echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
    read -p ""
    return # Return to menu
  fi

  echo -e "${CYAN}🌐 Server Connection Details:${RESET}" # Server Connection Details:
  echo -e "  (e.x., server.yourdomain.com:6060)"
  
  # Validate Server Address
  local server_addr
  while true; do
    echo -e "👉 ${WHITE}Server address and port (e.g., server.yourdomain.com:6060 or 192.168.1.1:6060):${RESET} " # Server address and port (e.g., server.yourdomain.com:6060 or 192.168.1.1:6060):
    read -p "" server_addr_input
    # Split into host and port for validation
    local host_part=$(echo "$server_addr_input" | cut -d':' -f1)
    local port_part=$(echo "$server_addr_input" | cut -d':' -f2)

    if validate_host "$host_part" && validate_port "$port_part"; then
      server_addr="$server_addr_input"
      break
    else
      print_error "Invalid server address or port format. Please use 'host:port' (e.g., example.com:6060)." # Invalid server address or port format. Please use 'host:port' (e.g., example.com:6060).
    fi
  done
  echo ""

  echo -e "${CYAN}📡 Tunnel Mode:${RESET}" # Tunnel Mode:
  echo -e "  (tcp/udp/both)"
  echo -e "👉 ${WHITE}Tunnel mode ? (tcp/udp/both):${RESET} " # Tunnel mode ? (tcp/udp/both):
  read -p "" tunnel_mode
  echo ""

  echo -e "🔑 ${WHITE}Password:${RESET} " # Password:
  read -p "" password
  echo ""

  echo -e "${CYAN}🔢 Port Mapping Configuration:${RESET}" # Port Mapping Configuration:
  echo -e "  ${WHITE}Supported formats:${RESET}"
  echo -e "    ${GREEN}Range:${RESET} 1000-1300 (ports 1000 to 1300)"
  echo -e "    ${GREEN}List:${RESET} 1000,1001,1002 (specific ports)"
  echo -e "    ${GREEN}Mixed:${RESET} 1000-1010,2000,3000-3005"
  echo ""
  
  local port_input
  local ports_array=()
  
  while true; do
    echo -e "👉 ${WHITE}Enter ports (range/list):${RESET} " # Enter ports (range/list):
    read -p "" port_input
    
    # Parse the input and extract ports
    if parse_ports "$port_input" ports_array; then
      if [ ${#ports_array[@]} -gt 0 ]; then
        echo -e "${GREEN}✅ Found ${#ports_array[@]} ports to tunnel.${RESET}" # Found ports to tunnel
      break
    else
        print_error "No valid ports found. Please try again." # No valid ports found
      fi
    else
      print_error "Invalid port format. Please use ranges (1000-1300) or comma-separated list (1000,1001)." # Invalid port format
    fi
  done
  echo ""
  
  # Build mappings from the parsed ports
  mappings=""
  for port in "${ports_array[@]}"; do
    mapping="IN^0.0.0.0:$port^0.0.0.0:$port"
    [ -z "$mappings" ] && mappings="$mapping" || mappings="$mappings,$mapping"
  done

  # Determine the mapping arguments based on the tunnel_mode
  mapping_args=""
  case "$tunnel_mode" in
    "tcp")
      mapping_args="--tcp-mappings \"$mappings\""
      ;;
    "udp")
      mapping_args="--udp-mappings \"$mappings\""
      ;;
    "both")
      mapping_args="--tcp-mappings \"$mappings\" --udp-mappings \"$mappings\""
      ;;
    *)
      echo -e "${YELLOW}⚠️ Invalid tunnel mode specified. Using 'both' as default.${RESET}" # Invalid tunnel mode specified. Using 'both' as default.
      mapping_args="--tcp-mappings \"$mappings\" --udp-mappings \"$mappings\""
      ;;
  esac

  # Remove old client configuration files
  rm -f "/root/rstun/frpc_${client_name}.ini" > /dev/null 2>&1
  
  # Create optimized frpc configuration file
  local config_file="/root/rstun/frpc_${client_name}.ini"
  create_optimized_client_config "$config_file" "$server_addr" "$password" "$client_name"

  # Add port mappings to config
  
  # Create configuration entries for each port
  for port in "${ports_array[@]}"; do
    if [[ "$tunnel_mode" == "tcp" || "$tunnel_mode" == "both" ]]; then
      cat <<EOF >> "$config_file"
[tcp_$port]
type = tcp
local_ip = 127.0.0.1
local_port = $port
remote_port = $port

EOF
    fi
    
    if [[ "$tunnel_mode" == "udp" || "$tunnel_mode" == "both" ]]; then
      cat <<EOF >> "$config_file"
[udp_$port]
type = udp
local_ip = 127.0.0.1
local_port = $port
remote_port = $port

EOF
    fi
  done

  # Create the systemd service file using a here-document
  cat <<EOF | sudo tee "$service_file" > /dev/null
[Unit]
Description=TrustTunnel Client - $client_name
After=network.target

[Service]
Type=simple
ExecStart=/root/rstun/frpc -c /root/rstun/frpc_${client_name}.ini
Restart=always
RestartSec=2
User=root

[Install]
WantedBy=multi-user.target
EOF

  echo -e "${CYAN}🔧 Reloading systemd daemon...${RESET}" # Reloading systemd daemon...
  sudo systemctl daemon-reload

  echo -e "${CYAN}🚀 Enabling and starting Trusttunnel client service...${RESET}" # Enabling and starting Trusttunnel client service...
  sudo systemctl enable "$service_name" > /dev/null 2>&1
  
  # Apply system optimizations for client
  apply_system_optimizations
  optimize_network_interface
  optimize_process_performance "$service_name"
  create_performance_monitor
  
  sudo systemctl start "$service_name" > /dev/null 2>&1

  print_success "Client '$client_name' started with maximum performance optimizations!" # Client 'client_name' started as service_name
  
  echo ""
  echo -e "${GREEN}🚀 Applied Optimizations:${RESET}"
  echo -e "  ${WHITE}• BBR Congestion Control${RESET}"
  echo -e "  ${WHITE}• TCP Window Scaling${RESET}"
  echo -e "  ${WHITE}• Network Buffer Optimization${RESET}"
  echo -e "  ${WHITE}• Process Priority Enhancement${RESET}"
  echo -e "  ${WHITE}• Memory Management Tuning${RESET}"
  echo -e "  ${WHITE}• Connection Pooling (16 pools)${RESET}"
  echo -e "  ${WHITE}• TCP Multiplexing${RESET}"
  echo -e "  ${WHITE}• Performance Monitoring${RESET}"
  echo -e "  ${WHITE}• ${#ports_array[@]} Ports Configured${RESET}"

  echo ""
  echo -e "${YELLOW}Do you want to view the logs for $client_name now? (y/N): ${RESET}" # Do you want to view the logs for client_name now? (y/N):
  read -p "" view_logs_choice
  echo ""

  if [[ "$view_logs_choice" =~ ^[Yy]$ ]]; then
    show_service_logs "$service_name"
  fi

  echo ""
  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
  read -p ""
}

# --- Initial Setup Function ---
# This function performs one-time setup tasks like installing dependencies
# and creating the 'trust' command symlink.
perform_initial_setup() {
  # Check if initial setup has already been performed
  if [ -f "$SETUP_MARKER_FILE" ]; then
    echo -e "${YELLOW}Initial setup already performed. Skipping prerequisites installation.${RESET}" # Updated message
    # Still ensure the trust command is available even if initial setup was skipped for dependencies
    ensure_trust_command_available
    return 0 # Exit successfully
  fi

  echo -e "${CYAN}Performing initial setup (installing dependencies and setting up 'trust' command)...${RESET}" # Performing initial setup (installing dependencies and setting up 'trust' command)...

  # Install required tools
  echo -e "${CYAN}Updating package lists and installing dependencies...${RESET}" # Updating package lists and installing dependencies...
  sudo apt update
  sudo apt install -y build-essential curl pkg-config libssl-dev git figlet cron ethtool net-tools htop iotop sysstat ethtool net-tools htop iotop sysstat

  # Ensure 'trust' command symlink is created/updated after initial setup
    if ensure_trust_command_available; then # Call the function and check its return status
      sudo mkdir -p "$(dirname "$SETUP_MARKER_FILE")" # Ensure directory exists for marker file
      sudo touch "$SETUP_MARKER_FILE" # Create marker file only if all initial setup steps (including symlink) succeed
      print_success "Initial setup complete and 'trust' command is ready." # Initial setup complete and 'trust' command is ready.
      return 0
    else
      print_error "Failed to set up 'trust' command symlink during initial setup. Please fix manually as instructed above." # Failed to set up 'trust' command symlink during initial setup. Please fix manually as instructed above.
      return 1 # Propagate failure
  fi
  echo ""
  return 0
}


# --- Main Script Execution ---
set -e # Exit immediately if a command exits with a non-zero status

# Perform initial setup (will run only once)
perform_initial_setup || { echo "Initial setup failed. Exiting."; exit 1; }

# Show initialization splash screen
echo -e "${CYAN}🚀 TrustTunnel - High Performance Mode${RESET}"
echo -e "${WHITE}Loading optimizations...${RESET}"
sleep 1

# Start main menu
while true; do
  # Clear terminal and show logo
  clear
  echo -e "${CYAN}"
  
  # Check if figlet is available, if not show a simple banner
  if command -v figlet &> /dev/null; then
  figlet -f slant "TrustTunnel"
  else
    # Fallback ASCII banner if figlet is not available
    echo "████████ ██████  ██    ██ ███████ ████████ ████████ ██    ██ ███    ██ ███    ██ ███████ ██      "
    echo "   ██    ██   ██ ██    ██ ██         ██       ██    ██    ██ ████   ██ ████   ██ ██      ██      "
    echo "   ██    ██████  ██    ██ ███████    ██       ██    ██    ██ ██ ██  ██ ██ ██  ██ █████   ██      "
    echo "   ██    ██   ██ ██    ██      ██    ██       ██    ██    ██ ██  ██ ██ ██  ██ ██ ██      ██      "
    echo "   ██    ██   ██  ██████  ███████    ██       ██     ██████  ██   ████ ██   ████ ███████ ███████ "
    echo ""
  fi
  
  echo -e "${CYAN}"
  echo -e "\033[1;33m=========================================================="
  echo -e "Developed by ErfanXRay => https://github.com/Erfan-XRay/TrustTunnel"
  echo -e "Telegram Channel => @Erfan_XRay"
  echo -e "\033[0m${WHITE}High-Performance Reverse Tunnel (TCP Multiplexing + BBR)${WHITE}${RESET}" # High-Performance Reverse Tunnel (TCP Multiplexing + BBR)
  draw_green_line
  echo -e "${GREEN}|${RESET}              ${WHITE}TrustTunnel Main Menu${RESET}                  ${GREEN}|${RESET}" # TrustTunnel Main Menu
  echo -e "${YELLOW}You can also run this script anytime by typing: ${WHITE}trust${RESET}" # New message for 'trust' command
  draw_green_line
  # Menu
  echo "Select an option:" # Select an option:
  echo -e "${MAGENTA}1) Install TrustTunnel${RESET}" # Install TrustTunnel
  echo -e "${CYAN}2) Tunnel Management${RESET}" # Tunnel Management
  echo -e "${GREEN}3) Performance Status${RESET}" # Performance Status
  echo -e "${YELLOW}4) Advanced Optimizations${RESET}" # Advanced Optimizations
  echo -e "${BLUE}5) Network Benchmark${RESET}" # Network Benchmark
  echo -e "${RED}6) Uninstall TrustTunnel${RESET}" # Uninstall TrustTunnel
  echo -e "${WHITE}7) Exit${RESET}" # Exit
  read -p "👉 Your choice: " choice # Your choice:

  case $choice in
    1)
      install_trusttunnel_action
      ;;
    2)
    clear # Clear screen for a fresh menu display
    echo ""
    draw_line "$GREEN" "=" 40 # Top border
    echo -e "${CYAN}        🌐 Choose Tunnel Mode${RESET}" # Choose Tunnel Mode
    draw_line "$GREEN" "=" 40 # Separator
    echo ""
    echo -e "  ${YELLOW}1)${RESET} ${MAGENTA}Server (Iran)${RESET}" # Server (Iran)
    echo -e "  ${YELLOW}2)${RESET} ${BLUE}Client (Kharej)${RESET}" # Client (Kharej)
    echo -e "  ${YELLOW}3)${RESET} ${WHITE}Return to main menu${RESET}" # Return to main menu
    echo ""
    draw_line "$GREEN" "-" 40 # Bottom border
    echo -e "👉 ${CYAN}Your choice:${RESET} " # Your choice:
    read -p "" tunnel_choice # Removed prompt from read -p
    echo "" # Add a blank line for better spacing after input

      case $tunnel_choice in
        1)
          clear

          # Server Management Sub-menu
          while true; do
            clear # Clear screen for a fresh menu display
            echo ""
            draw_line "$GREEN" "=" 40 # Top border
            echo -e "${CYAN}        🔧 TrustTunnel Server Management${RESET}" # TrustTunnel Server Management
            draw_line "$GREEN" "=" 40 # Separator
            echo ""
            echo -e "  ${YELLOW}1)${RESET} ${WHITE}Add new server${RESET}" # Add new server
            echo -e "  ${YELLOW}2)${RESET} ${WHITE}Show service logs${RESET}" # Show service logs
            echo -e "  ${YELLOW}3)${RESET} ${WHITE}Delete service${RESET}" # Delete service
            echo -e "  ${YELLOW}4)${RESET} ${MAGENTA}Schedule server restart${RESET}" # Schedule server restart
            echo -e "  ${YELLOW}5)${RESET} ${RED}Delete scheduled restart${RESET}" # New option: Delete scheduled restart
            echo -e "  ${YELLOW}6)${RESET} ${WHITE}Back to main menu${RESET}" # Back to main menu
            echo ""
            draw_line "$GREEN" "-" 40 # Bottom border
            echo -e "👉 ${CYAN}Your choice:${RESET} " # Your choice:
            read -p "" srv_choice
            echo ""
            case $srv_choice in
              1)
                add_new_server_action
              ;;
              2)
                clear
                service_file="/etc/systemd/system/trusttunnel.service"
                if [ -f "$service_file" ]; then
                  show_service_logs "trusttunnel.service"
                else
                  echo -e "${RED}❌ Service 'trusttunnel.service' not found. Cannot show logs.${RESET}" # Service 'trusttunnel.service' not found. Cannot show logs.
                  echo ""
                  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
                  read -p ""
                fi
              ;;
              3)
                clear
                service_file="/etc/systemd/system/trusttunnel.service"
                if [ -f "$service_file" ]; then
                  echo -e "${YELLOW}🛑 Stopping and deleting trusttunnel.service...${RESET}" # Stopping and deleting trusttunnel.service...
                  sudo systemctl stop trusttunnel.service > /dev/null 2>&1
                  sudo systemctl disable trusttunnel.service > /dev/null 2>&1
                  sudo rm -f "$service_file" > /dev/null 2>&1
                  sudo systemctl daemon-reload > /dev/null 2>&1
                  print_success "Service deleted." # Service deleted.
                else
                  echo -e "${RED}❌ Service 'trusttunnel.service' not found. Nothing to delete.${RESET}" # Service 'trusttunnel.service' not found. Nothing to delete.
                fi
                echo ""
                echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
                  read -p ""
              ;;
              4) # Schedule server restart
                reset_timer "trusttunnel" # Pass the server service name directly
              ;;
              5) # New case for deleting cron job
                delete_cron_job_action
              ;;
              6)
                break
              ;;
              *)
                echo -e "${RED}❌ Invalid option.${RESET}" # Invalid option.
                echo ""
                echo -e "${YELLOW}Press Enter to continue...${RESET}" # Press Enter to continue...
                read -p ""
              ;;
            esac
          done
          ;;
        2)
          clear

          while true; do
            clear # Clear screen for a fresh menu display
            echo ""
            draw_line "$GREEN" "=" 40 # Top border
            echo -e "${CYAN}        📡 TrustTunnel Client Management${RESET}" # TrustTunnel Client Management
            draw_line "$GREEN" "=" 40 # Separator
            echo ""
            echo -e "  ${YELLOW}1)${RESET} ${WHITE}Add new client${RESET}" # Add new client
            echo -e "  ${YELLOW}2)${RESET} ${WHITE}Show Client Log${RESET}" # Show Client Log
            echo -e "  ${YELLOW}3)${RESET} ${WHITE}Delete a client${RESET}" # Delete a client
            echo -e "  ${YELLOW}4)${RESET} ${BLUE}Schedule client restart${RESET}" # Schedule client restart
            echo -e "  ${YELLOW}5)${RESET} ${RED}Delete scheduled restart${RESET}" # New option: Delete scheduled restart
            echo -e "  ${YELLOW}6)${RESET} ${WHITE}Back to main menu${RESET}" # Back to main menu
            echo ""
            draw_line "$GREEN" "-" 40 # Bottom border
            echo -e "👉 ${CYAN}Your choice:${RESET} " # Your choice:
            read -p "" client_choice
            echo ""

            case $client_choice in
              1)
                add_new_client_action
              ;;
              2)
                clear
                echo ""
                draw_line "$CYAN" "=" 40
                echo -e "${CYAN}        📊 TrustTunnel Client Logs${RESET}" # TrustTunnel Client Logs
                draw_line "$CYAN" "=" 40
                echo ""

                echo -e "${CYAN}🔍 Searching for clients ...${RESET}" # Searching for clients ...

                # List all systemd services that start with trusttunnel-
                mapfile -t services < <(systemctl list-units --type=service --all | grep 'trusttunnel-' | awk '{print $1}' | sed 's/.service$//')

                if [ ${#services[@]} -eq 0 ]; then
                  echo -e "${RED}❌ No clients found.${RESET}" # No clients found.
                  echo ""
                  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
                  # No return here, let the loop continue to show client management menu
                else
                  echo -e "${CYAN}📋 Please select a service to see log:${RESET}" # Please select a service to see log:
                  # Add "Back to previous menu" option
                  services+=("Back to previous menu")
                  select selected_service in "${services[@]}"; do
                    if [[ "$selected_service" == "Back to previous menu" ]]; then
                      echo -e "${YELLOW}Returning to previous menu...${RESET}" # Returning to previous menu...
                      echo ""
                      break 2 # Exit both the select and the outer while loop
                    elif [ -n "$selected_service" ]; then
                      show_service_logs "$selected_service"
                      break # Exit the select loop
                    else
                      echo -e "${RED}⚠️ Invalid selection. Please enter a valid number.${RESET}" # Invalid selection. Please enter a valid number.
                    fi
                  done
                  echo "" # Add a blank line after selection
                  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
                  read -p ""
                fi
              ;;
              3)
                clear
                echo ""
                draw_line "$CYAN" "=" 40
                echo -e "${CYAN}        🗑️ Delete TrustTunnel Client${RESET}" # Delete TrustTunnel Client
                draw_line "$CYAN" "=" 40
                echo ""

                echo -e "${CYAN}🔍 Searching for clients ...${RESET}" # Searching for clients ...

                # List all systemd services that start with trusttunnel-
                mapfile -t services < <(systemctl list-units --type=service --all | grep 'trusttunnel-' | awk '{print $1}' | sed 's/.service$//')

                if [ ${#services[@]} -eq 0 ]; then
                  echo -e "${RED}❌ No clients found.${RESET}" # No clients found.
                  echo ""
                  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
                  # No return here, let the loop continue to show client management menu
                else
                  echo -e "${CYAN}📋 Please select a service to delete:${RESET}" # Please select a service to delete:
                  # Add "Back to previous menu" option
                  services+=("Back to previous menu")
                  select selected_service in "${services[@]}"; do
                    if [[ "$selected_service" == "Back to previous menu" ]]; then
                      echo -e "${YELLOW}Returning to previous menu...${RESET}" # Returning to previous menu...
                      echo ""
                      break 2 # Exit both the select and the outer while loop
                    elif [ -n "$selected_service" ]; then
                      service_file="/etc/systemd/system/${selected_service}.service"
                      echo -e "${YELLOW}🛑 Stopping $selected_service...${RESET}" # Stopping selected_service...
                      sudo systemctl stop "$selected_service" > /dev/null 2>&1
                      sudo systemctl disable "$selected_service" > /dev/null 2>&1
                      sudo rm -f "$service_file" > /dev/null 2>&1
                      sudo systemctl daemon-reload > /dev/null 2>&1
                      print_success "Client '$selected_service' deleted." # Client 'selected_service' deleted.
                      # Also remove any associated cron jobs for this specific client
                      echo -e "${CYAN}🧹 Removing cron jobs for '$selected_service'...${RESET}" # Removing cron jobs for 'selected_service'...
                      (sudo crontab -l 2>/dev/null | grep -v "# TrustTunnel automated restart for $selected_service$") | sudo crontab -
                      print_success "Cron jobs for '$selected_service' removed." # Cron jobs for 'selected_service' removed.
                      break # Exit the select loop
                    else
                      echo -e "${RED}⚠️ Invalid selection. Please enter a valid number.${RESET}" # Invalid selection. Please enter a valid number.
                    fi
                  done
                  echo "" # Add a blank line after selection
                  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
                  read -p ""
                fi
              ;;
              4) # Schedule client restart
                clear
                echo ""
                draw_line "$CYAN" "=" 40
                echo -e "${CYAN}        ⏰ Schedule Client Restart${RESET}" # Schedule Client Restart
                draw_line "$CYAN" "=" 40
                echo ""

                echo -e "${CYAN}🔍 Searching for clients ...${RESET}" # Searching for clients ...

                mapfile -t services < <(systemctl list-units --type=service --all | grep 'trusttunnel-' | awk '{print $1}' | sed 's/.service$//')

                if [ ${#services[@]} -eq 0 ]; then
                  echo -e "${RED}❌ No clients found to schedule. Please add a client first.${RESET}" # No clients found to schedule. Please add a client first.
                  echo ""
                  echo -e "${YELLOW}Press Enter to return to previous menu...${RESET}" # Press Enter to return to previous menu...
                  read -p ""
                else
                  echo -e "${CYAN}📋 Please select which client service to schedule for restart:${RESET}" # Please select which client service to schedule for restart:
                  # Add "Back to previous menu" option
                  services+=("Back to previous menu")
                  select selected_client_service in "${services[@]}"; do
                    if [[ "$selected_client_service" == "Back to previous menu" ]]; then
                      echo -e "${YELLOW}Returning to previous menu...${RESET}" # Returning to previous menu...
                      echo ""
                      break 2 # Exit both the select and the outer while loop
                    elif [ -n "$selected_client_service" ]; then
                      reset_timer "$selected_client_service" # Pass the selected client service name
                      break # Exit the select loop
                    else
                      echo -e "${RED}⚠️ Invalid selection. Please enter a valid number.${RESET}" # Invalid selection. Please enter a valid number.
                    fi
                  done
                fi
              ;;
              5) # New case for deleting cron job in client menu
                delete_cron_job_action
              ;;
              6)
                break
              ;;
              *)
                echo -e "${RED}❌ Invalid option.${RESET}" # Invalid option.
                echo ""
                echo -e "${YELLOW}Press Enter to continue...${RESET}" # Press Enter to continue...
                read -p ""
              ;;
            esac
          done
          ;;
        3)
          break # Return to main menu
          ;;
        *)
          echo -e "${RED}❌ Invalid option.${RESET}" # Invalid option.
          echo ""
          echo -e "${YELLOW}Press Enter to continue...${RESET}" # Press Enable to continue...
          read -p ""
          ;;
      esac
    ;;
    3)
      show_performance_status
    ;;
    4)
      apply_additional_optimizations
    ;;
    5)
      run_network_benchmark
    ;;
    6)
      uninstall_trusttunnel_action
    ;;
    7)
      exit 0
    ;;
    *)
      echo -e "${RED}❌ Invalid choice. Exiting.${RESET}" # Invalid choice. Exiting.
      echo ""
      echo -e "${YELLOW}Press Enter to continue...${RESET}" # Press Enter to continue...
      read -p ""
    ;;
  esac
  echo ""
done
