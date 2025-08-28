#!/bin/bash
# IPTables setup script with SSH protection, auto-detect SSH port,
# automatic rollback after 180 seconds if SSH connection fails

# --------------------------------------------------
# Define ports to allow
# --------------------------------------------------
# TCP ports or ranges. Example: (80 443 1000:2000)
TCP_PORTS=(443)

# UDP ports or ranges. Example: (80 443 1000:2000)
UDP_PORTS=(443 51820:51830)
# --------------------------------------------------

ROLLBACK_FILE="/root/iptables.backup"

CYAN="\e[36m"
GREEN="\e[32m"
YELLOW="\e[33m"
RED="\e[31m"
RESET="\e[0m"

# -------------------------------
# Detect Linux distribution
# -------------------------------
if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
else
    echo -e "${RED}[ALERT]${RESET} Cannot detect Linux distribution!"
    exit 1
fi

# -------------------------------
# Check if system is Debian/Ubuntu or derivative
# -------------------------------
if [ -n "$ID_LIKE" ] && echo "$ID_LIKE" | grep -iq "debian"; then
  # Install iptables and iptables-persistent if needed
  echo -e "${CYAN}[INFO]${RESET} Debian/Ubuntu or derivative detected: $NAME"
  if ! command -v iptables >/dev/null 2>&1 || ! dpkg -s iptables-persistent >/dev/null 2>&1; then
    echo -e "${CYAN}[INFO]${RESET} Installing iptables and iptables-persistent..."
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq iptables iptables-persistent >/dev/null 2>&1
    if ! command -v iptables >/dev/null 2>&1 || ! dpkg -s iptables-persistent >/dev/null 2>&1; then
      echo -e "${RED}[ALERT]${RESET} Installation failed! Exiting."
      exit 1
    fi
    echo -e "${CYAN}[INFO]${RESET} iptables and iptables-persistent installed successfully."
  else
      echo -e "${CYAN}[INFO]${RESET} iptables and iptables-persistent are already installed."
  fi

  # Disable UFW if active
  if command -v ufw >/dev/null 2>&1; then
    UFW_ACTIVE=0

    # Check if ufw is active via status command
    if ufw status | grep -q "Status: active"; then
      UFW_ACTIVE=1
    fi

    # Check if ufw is active via systemctl
    if command -v systemctl >/dev/null 2>&1; then
      if systemctl is-active --quiet ufw; then
        UFW_ACTIVE=1
      fi
    fi

    if [ $UFW_ACTIVE -eq 1 ]; then
      echo -e "${YELLOW}[WARNING]${RESET} UFW is active. Disabling UFW to avoid conflicts..."

      # Disable via ufw command
      ufw disable >/dev/null 2>&1

      # Stop and disable service via systemctl if available
      if command -v systemctl >/dev/null 2>&1; then
        systemctl stop ufw >/dev/null 2>&1
        systemctl disable ufw >/dev/null 2>&1
      fi

      echo -e "${CYAN}[INFO]${RESET} UFW disabled successfully."
    fi
  fi
else
  echo -e "${RED}[ALERT]${RESET} Unsupported Linux distribution: $NAME"
  exit 1
fi

# -------------------------------
# Detect the active SSH port automatically
# -------------------------------
SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | sed 's/.*://g' | head -n 1)
if [ -z "$SSH_PORT" ]; then
  echo -e "${YELLOW}[WARNING]${RESET} Could not detect SSH port. Using default port 22."
  SSH_PORT=22
else
  echo -e "${CYAN}[INFO]${RESET} Detected SSH port: $SSH_PORT"
fi

# -------------------------------
# Save current rules for rollback
# -------------------------------
echo -e "${CYAN}[INFO]${RESET} Saving current iptables rules for rollback..."
iptables-save > "$ROLLBACK_FILE"

# -------------------------------
# Start rollback timer in background
# -------------------------------
(
  sleep 180
  # Check if SSH connection is still active
  if ! ss -tlnp | grep -q ":$SSH_PORT"; then
    echo -e "${RED}[ALERT]${RESET} SSH not active! Rolling back iptables rules..."
    iptables-restore < "$ROLLBACK_FILE"
    echo -e "${CYAN}[INFO]${RESET} Rules have been restored."
  else
    echo -e "${CYAN}[INFO]${RESET} SSH is active. Rollback not needed."
  fi
) &

TIMER_PID=$!
echo -e "${CYAN}[INFO]${RESET} Rollback timer started in background with PID: $TIMER_PID"

# -------------------------------
# Apply new iptables rules
# -------------------------------
# Flush all existing rules and custom chains
iptables -F
iptables -X

# Allow SSH and loopback interface
iptables -A INPUT -p tcp --dport "$SSH_PORT" -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow TCP ports from array
for port in "${TCP_PORTS[@]}"; do
  iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
  echo -e "${CYAN}[INFO]${RESET} TCP port $port allowed"
done

# Allow UDP ports from array
for port in "${UDP_PORTS[@]}"; do
  iptables -A INPUT -p udp --dport "$port" -j ACCEPT
  echo -e "${CYAN}[INFO]${RESET} UDP port $port allowed"
done

# Set default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

echo -e "${CYAN}[INFO]${RESET} IPTables rules applied."
echo -e "${CYAN}[INFO]${RESET} SSH port $SSH_PORT is open. Loopback and existing connections allowed."

# -------------------------------
# Save rules permanently
# -------------------------------
echo -e "${CYAN}[INFO]${RESET} Saving rules..."
netfilter-persistent save >/dev/null 2>&1

# -------------------------------
# Show current rules
# -------------------------------
iptables -L -n -v

echo -e "${CYAN}[INFO]${RESET} IPTables setup completed successfully! \n"
echo -e "${YELLOW}[*] If everything works, stop the auto-rollback timer with the command: ${GREEN}kill $TIMER_PID${RESET}"
