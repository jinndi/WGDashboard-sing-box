#!/bin/bash
#
# https://github.com/jinndi/WGDashboard-sing-box
#
# Copyright (c) 2025 Jinndi <alncores@gmail.ru>
#
# Released under the MIT License, see the accompanying file LICENSE
# or https://opensource.org/licenses/MIT

export DEBIAN_FRONTEND=noninteractive
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

## Paths:
path_xray_dir="/opt/xray"
path_xray="$path_xray_dir/Xray-core"
path_service="/etc/systemd/system/xray.service"
path_server_config="$path_xray_dir/config.json"
path_client_links="$path_xray_dir/client.links"
path_sysctl_config="/etc/sysctl.d/99-xray.conf"
path_script="$path_xray_dir/xray"
path_script_link="/usr/bin/xray"

## Version Xray-core
# https://github.com/XTLS/Xray-core/releases
version=""
if [[ -f "$path_xray" ]]; then
  version="v$("$path_xray" version | awk 'NR==1 {print $2}' | xargs)"
else
  version=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
fi

## Cloaking domain
SERVER_NAME=""

show_header() {
echo -e "\033[1;35m"
cat <<EOF
################################################
 XRAY SERVER $version
 https://github.com/jinndi/WGDashboard-sing-box
################################################
EOF
echo -e "\033[0m"
}

echomsg() {
  [ -n "$2" ] && echo
  echo -e "\033[1;34m$1\033[0m"
}

echook() {
  echo -e "\033[1;32m$1\033[0m"
}

echoerr () {
  echo -e "\033[1;31m$1\033[0m"
}

exiterr() {
  echo -e "\033[1;31mError: $1\033[0m" >&2
  exit 1
}

check_root() {
  if [ "$(id -u)" != 0 ]; then
    exiterr "Installer must be launched on behalf of root 'sudo bash $0'"
  fi
}

check_shell() {
  if readlink /proc/$$/exe | grep -q "dash"; then
    exiterr "Installer must be launched using «bash», and not «sh»"
  fi
}

check_os() {
  if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
  elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
  else
    exiterr "Installer supports only Ubuntu and Debian!"
  fi
}

check_os_ver() {
  if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
    exiterr "To use installer, Ubuntu 18.04 or a later version is required"
  fi
  if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
    exiterr "To use installer, DEBIAN 10 or later version is required"
  fi
}

check_kernel() {
  if [[ $(uname -r | cut -d "." -f 1) -lt 4 ]]; then
     exiterr "For installation, nucleus OS version is necessary >= 4"
  fi
}

check_container() {
  if systemd-detect-virt -cq 2>/dev/null; then
    exiterr "Installation inside a container is not available"
  fi
}

check_IPv4() {
  if [[ ! "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echoerr "Incorrect format IPv4 addresses"
    return 1
  fi

  IFS='.' read -r -a octets <<< "$1"
  for octet in "${octets[@]}"; do
    if [[ "$octet" != "0" && "$octet" =~ ^0 ]]; then
      echoerr "Octet IPv4 with leading zero is unacceptable"
      return 1
    fi

    dec_octet=$((10#$octet))
    if ((dec_octet < 0 || dec_octet > 255)); then
      echoerr "Wrong range of octet IPv4"
      return 1
    fi
  done

  return 0
}

get_public_ip() {
  local public_ip

  public_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')

  [ -z "$public_ip" ] && command -v dig >/dev/null && \
    public_ip=$(dig +short -4 myip.opendns.com @resolver1.opendns.com)

  [ -z "$public_ip" ] && command -v curl >/dev/null && \
    public_ip=$(curl -s https://api.ipify.org)

  if ! check_IPv4 "$public_ip"; then
    echoerr "Failed to determine the public IP"

    while true; do
      echomsg "Enter IPv4 address of this server" 1
      read -rp " > " public_ip
      if check_IPv4 "$public_ip"; then break; fi
    done
  fi

  echo "$public_ip"
}

wait_for_apt_unlock() {
  local timeout=300
  local waited=0

  while pgrep -x apt >/dev/null || pgrep -x apt-get >/dev/null || pgrep -x dpkg >/dev/null; do
    sleep 1
    [ "$waited" = 0 ] && echomsg "Waiting for the completion of APT/DPKG processes..." 1
    ((waited++))
    if (( waited >= timeout )); then
      exiterr "Exceeding waiting time ($timeout s.)."
    fi
  done
}

install_pkgs() {
  tput civis 
  wait_for_apt_unlock

  local cmds=(
    "apt-get -yqq update"
    "apt-get -yqq upgrade"
    "apt-get -yqq install iproute2 iptables openssl lsof dnsutils unzip"
  )
  local cmd status

  echomsg "Package updating and installing dependencies" 1
  for cmd in "${cmds[@]}"; do
    echo " > $cmd"
    eval "$cmd" > /dev/null 2>&1
    status=$?
    [[ $status -ne 0 ]] && exiterr "'$cmd' failed"
  done
  tput cnorm
}

check_443port() {
  echomsg "Checking the availability of port 443" 1
  if lsof -i :"443" >/dev/null; then
    exiterr "Port 443 is busy"
  fi
  return 0
}

get_random_free_port() {
  local port
  while :; do
    port=$(shuf -i 1024-65535 -n 1)
    if ! lsof -i :"$port" >/dev/null 2>&1; then
      echo "$port"
      return
    fi
  done
}

input_server_name() {
  echomsg "Enter or select a masking domain from suggested options:" 1
  echo -e " 1) github.com\n 2) microsoft.com\n 3) samsung.com\n 4) nvidia.com\n 5) amd.com"

  read -rp " > " option
  until [[ "$option" =~ ^[1-5]$ || "$option" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; do
    echoerr "Incorrect option"
    read -rp " > " option
  done

  case "$option" in
    1)
      SERVER_NAME="github.com"
    ;;
    2)
      SERVER_NAME="microsoft.com"
    ;;
    3)
      SERVER_NAME="samsung.com"
    ;;
    4)
      SERVER_NAME="nvidia.com"
    ;;
    5)
      SERVER_NAME="amd.com"
    ;;
    *)
      SERVER_NAME="$option"
    ;;
  esac
}

download_xray() {
  tput civis
  echomsg "Download XRay $version" 1

  mkdir -p "$(dirname "$path_xray")" || exiterr "mkdir failed"

  curl -fsSL -o xray.zip "https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-64.zip" \
    || exiterr "XRay curl download failed"

  unzip -o ./xray.zip -d "$path_xray_dir" > /dev/null 2>&1 \
    || exiterr "XRay unzip failed"

  mv "$path_xray_dir/xray" "$path_xray" > /dev/null 2>&1 \
    || exiterr "XRay mv failed"

  chmod +x "$path_xray" > /dev/null 2>&1 || exiterr "XRay chmod failed"
  
  rm -f ./xray.zip > /dev/null 2>&1 || exiterr "XRay rm failed"
  tput cnorm
}

create_sysctl_config () {
  tput civis
  echomsg "Creating network settings" 1

  mkdir -p "$(dirname "$path_sysctl_config")"

  {
    echo "# Network configuration for server 1+ GB RAM"
    echo "# https://www.kernel.org/doc/Documentation/sysctl/net.txt"
    echo "# https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt"
    echo
    echo "fs.file-max = 51200"
    echo "net.core.rmem_max = 16777216"
    echo "net.core.wmem_max = 16777216"
    echo "net.core.rmem_default = 262144"
    echo "net.core.wmem_default = 262144"
    echo "net.core.netdev_max_backlog = 4096"
    echo "net.core.somaxconn = 4096"
    echo "net.ipv4.ip_forward = 1"
    echo "net.ipv4.conf.all.src_valid_mark = 1"
    echo "net.ipv6.conf.all.disable_ipv6 = 0"
    echo "net.ipv6.conf.all.forwarding = 1"
    echo "net.ipv6.conf.default.forwarding = 1"
    echo "net.ipv4.icmp_echo_ignore_all = 1"
    echo "net.ipv4.tcp_mem = 8192 16384 32768"
    echo "net.ipv4.tcp_rmem = 4096 87380 16777216"
    echo "net.ipv4.tcp_wmem = 4096 65536 16777216"
    echo "net.ipv4.udp_mem = 8192 16384 32768"
    echo "net.ipv4.udp_rmem_min = 16384"
    echo "net.ipv4.udp_wmem_min = 16384"
    echo "net.ipv4.tcp_syncookies = 1"
    echo "net.ipv4.tcp_tw_reuse = 1"
    echo "net.ipv4.tcp_fin_timeout = 30"
    echo "net.ipv4.tcp_keepalive_time = 600"
    echo "net.ipv4.tcp_keepalive_probes = 5"
    echo "net.ipv4.tcp_keepalive_intvl = 10"
    echo "net.ipv4.tcp_timestamps = 0"
    echo "net.ipv4.tcp_sack = 1"
    echo "net.ipv4.tcp_limit_output_bytes = 262144"
    echo "net.ipv4.ip_unprivileged_port_start = 1024"
    echo "net.ipv4.ip_local_port_range = 10000 60001"
    echo "net.ipv4.tcp_max_syn_backlog = 4096"
    echo "net.ipv4.tcp_max_tw_buckets = 4000"
    echo "net.ipv4.tcp_fastopen = 3"
    echo "net.ipv4.tcp_mtu_probing = 1"
    echo
    echo "## tcp_congestion_control"
    echo "# Algorithm for control of network overload"
    echo "# Full list of algorithms that can be available:"
    echo "# https://en.wikipedia.org/wiki/TCP_congestion-avoidance_algorithm#Algorithms"
    echo "# BBR - from Google (set in priority)"
    echo "# HYBLA - for networks with high delay"
    echo "# Cubic - for low delay networks"

  } > "$path_sysctl_config"
  
  if modprobe -q tcp_bbr && [ -f /proc/sys/net/ipv4/tcp_congestion_control ]
  then
    {
      echo "net.core.default_qdisc = fq"
      echo "net.ipv4.tcp_congestion_control = bbr"
    } >> "$path_sysctl_config"
  else
    if modprobe -q tcp_hybla && [ -f /proc/sys/net/ipv4/tcp_congestion_control ]
    then
      echo "net.ipv4.tcp_congestion_control = hybla" >> "$path_sysctl_config"
    fi
  fi

  sysctl -e -q -p "$path_sysctl_config"
  tput cnorm
}

create_configs() {
  tput civis
  local CLIENT_ID KEYS PRIVATE_KEY SHORT_ID DEST PUBLIC_IP
  local VLESS_LINK SS_BASE64 SS_LINK
  echomsg "Create a configs XRay" 1

  mkdir -p "$(dirname "$path_server_config")"
  mkdir -p "$(dirname "$path_client_links")"
  CLIENT_ID=$("$path_xray" uuid)
  KEYS=$("$path_xray" x25519)
  PRIVATE_KEY=$(echo "$KEYS" | grep 'Private key' | awk '{print $NF}')
  PUBLIC_KEY=$(echo "$KEYS" | grep 'Public key' | awk '{print $NF}')
  SHORT_ID=$(openssl rand -hex 3)
  DEST="$SERVER_NAME:443"
  PUBLIC_IP=$(get_public_ip)
  SS2022_PORT=$(get_random_free_port)
  SS2022_PSK=$(openssl rand -base64 16)
  
  # Server config
  {
    echo "{"
    echo "  \"log\": {"
    echo "    \"loglevel\": \"warn\""
    echo "  },"
    echo "  \"inbounds\": ["
    echo "    {"
    echo "      \"port\": 443,"
    echo "      \"protocol\": \"vless\","
    echo "      \"settings\": {"
    echo "        \"clients\": ["
    echo "          {"
    echo "            \"id\": \"$CLIENT_ID\","
    echo "            \"flow\": \"xtls-rprx-vision\""
    echo "          }"
    echo "        ],"
    echo "        \"decryption\": \"none\""
    echo "      },"
    echo "      \"streamSettings\": {"
    echo "        \"network\": \"tcp\","
    echo "        \"security\": \"reality\","
    echo "        \"realitySettings\": {"
    echo "          \"privateKey\": \"$PRIVATE_KEY\","
    echo "          \"shortIds\": [\"$SHORT_ID\"],"
    echo "          \"dest\": \"$DEST\","
    echo "          \"serverNames\": [\"$SERVER_NAME\"]"
    echo "        }"
    echo "      },"
    echo "      \"sniffing\": {"
    echo "        \"enabled\": true,"
    echo "        \"destOverride\": [\"http\", \"tls\", \"quic\"],"
    echo "        \"routeOnly\": true"
    echo "      }"
    echo "    },"
    echo "    {"
    echo "      \"port\": $SS2022_PORT,"
    echo "      \"protocol\": \"shadowsocks\","
    echo "      \"settings\": {"
    echo "        \"method\": \"2022-blake3-aes-128-gcm\","
    echo "        \"password\": \"$SS2022_PSK\","
    echo "        \"network\": \"tcp,udp\""
    echo "      }"
    echo "    }"
    echo "  ],"
    echo "  \"outbounds\": ["
    echo "    {"
    echo "      \"protocol\": \"freedom\","
    echo "      \"tag\": \"direct\""
    echo "    }"
    echo "  ]"
    echo "}"
  } > "$path_server_config"

  # Client VLESS over TCP with REALITY and XTLS-RPRX-Vision link
  # vless://<UUID>@<host>:<port>?security=reality&encryption=none&flow=xtls-rprx-vision&pbk=<base64-encoded-public-key>&sid=<shortID>&sni=<server-name>&fp=<fingerprint>
  VLESS_LINK="vless://$CLIENT_ID@$PUBLIC_IP:443?security=reality&encryption=none&flow=xtls-rprx-vision&pbk=$PUBLIC_KEY&sid=$SHORT_ID&sni=$SERVER_NAME&fp=chrome"

  # Client Shadowsocks-2022 (2022-blake3-aes-128-gcm) link 
  # ss://<base64-encoded-method:password>@<host>:<port>
  SS_BASE64=$(echo -n "2022-blake3-aes-128-gcm:$SS2022_PSK" | base64)
  SS_LINK="ss://$SS_BASE64@$PUBLIC_IP:$SS2022_PORT"

  {
    echo -e "\n"
    echo "-----------------------------------------------------" 
    echo "- VLESS over TCP with REALITY and XTLS-RPRX-Vision  -"
    echo "-----------------------------------------------------"
    echo "$VLESS_LINK"
    echo -e "\n"
    echo "-----------------------------------------------------"
    echo "- Shadowsocks-2022 (2022-blake3-aes-128-gcm) link:  -"
    echo "-----------------------------------------------------"
    echo "$SS_LINK"
    echo -e "\n"
  } > "$path_client_links"
  tput cnorm
}

create_service() {
  tput civis
  local FSIP DIF iptables_path

  echomsg "Creating systemd service" 1

  FSIP=$(dig +short "$SERVER_NAME" | grep -Eo '^[0-9.]+$' | head -n1)
  DIF=$(ip route | awk '/default/ {print $5}' | head -n1)

  # Path to iptables
  iptables_path=$(command -v iptables)
  if [[ $(systemd-detect-virt) == "openvz" ]] && \
    readlink -f "$(command -v iptables)" | grep -q "nft" && \
    hash iptables-legacy 2>/dev/null
  then
    iptables_path=$(command -v iptables-legacy)
  fi

  {
    echo "[Unit]"
    echo "Description=XRay server ${version}"
    echo "Documentation=https://github.com/XTLS/Xray-core"
    echo "After=network.target"
    echo "Wants=network.target"
    echo
    echo "[Service]"
    echo "PermissionsStartOnly=true"
    echo "ExecStartPre=${iptables_path} -I INPUT -p tcp --dport 443 -j ACCEPT"
    echo "ExecStartPre=${iptables_path} -t nat -A PREROUTING -i ${DIF} -p udp --dport 443 -j DNAT --to-destination ${FSIP}:443"
    echo "ExecStartPre=${iptables_path} -t nat -A PREROUTING -i ${DIF} -p tcp --dport 80 -j DNAT --to-destination ${FSIP}:80"
    echo "ExecStartPre=${iptables_path} -I INPUT -p tcp --dport ${SS2022_PORT} -j ACCEPT"
    echo "ExecStartPre=${iptables_path} -I INPUT -p udp --dport ${SS2022_PORT} -j ACCEPT"
    echo "ExecStart=${path_xray} -c ${path_server_config}"
    echo "ExecStopPost=${iptables_path} -D INPUT -p tcp --dport 443 -j ACCEPT"
    echo "ExecStopPost=${iptables_path} -t nat -D PREROUTING -i ${DIF} -p udp --dport 443 -j DNAT --to-destination ${FSIP}:443"
    echo "ExecStopPost=${iptables_path} -t nat -D PREROUTING -i ${DIF} -p tcp --dport 80 -j DNAT --to-destination ${FSIP}:80"
    echo "ExecStopPost=${iptables_path} -D INPUT -p tcp --dport ${SS2022_PORT} -j ACCEPT"
    echo "ExecStopPost=${iptables_path} -D INPUT -p udp --dport ${SS2022_PORT} -j ACCEPT"
    echo "Restart=on-failure"
    echo "User=xray"
    echo "LimitNOFILE=51200"
    echo "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
    echo "AmbientCapabilities=CAP_NET_BIND_SERVICE"
    echo "NoNewPrivileges=true"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > "$path_service"
  tput cnorm
}

add_user() {
  tput civis
  echomsg "Add user 'xray'" 1
  if ! id -u xray >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin xray \
      >/dev/null 2>&1 || exiterr "'useradd xray' failed"
  fi
  tput cnorm
}

activate_xray() {
  tput civis
  echomsg "Starting the service" 1
  systemctl daemon-reload >/dev/null 2>&1
  systemctl enable --now xray >/dev/null 2>&1
  if systemctl is-active --quiet xray; then
    echook "The service is successfully launched"
  else
    echoerr "Launch of service failed"
  fi
  tput cnorm
}

press_any_side_to_open_menu() {
  tput civis
  echomsg "------------------------------------------------"
  read -n1 -r -p "Press any key to open menu..."
  tput cnorm
  select_menu_option
}

switch_active_service() {
  tput civis
  systemctl daemon-reload >/dev/null 2>&1
  if systemctl is-active --quiet xray; then
    echomsg "Stop service" 1
    { systemctl stop xray && systemctl disable xray; } >/dev/null 2>&1
    sleep 2
    if systemctl is-active --quiet xray; then
      echoerr "The service stop failed"
    else
      echook "The service is successfully stopped"
    fi
  else
    echomsg "Starting the server" 1
    systemctl enable --now xray >/dev/null 2>&1
    sleep 2
    if systemctl is-active --quiet xray; then
      echook "Service is successfully launched"
    else
      echoerr "Launch of service failed"
    fi
  fi
  tput cnorm
  press_any_side_to_open_menu
}

restart_service() {
  tput civis
  echomsg "Restart service" 1
  systemctl daemon-reload >/dev/null 2>&1
  systemctl restart xray >/dev/null 2>&1
  sleep 2
  if systemctl is-active --quiet xray; then
    echook "Service is successfully restarted"
  else
    echoerr "Error restart service"
  fi
  tput cnorm
  press_any_side_to_open_menu
}

show_connect_links() {
  clear
  show_header

  echo -e "\033[0;36mXRay client linsks:\033[0m"
  cat "$path_client_links"

  echo -e "\nSelect option:"
  echo -e " 1) ✨ Recreate links\n 2) 📖 Back menu"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-2]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
  case "$option" in
    1)
      recreate_links
    ;;
    2)
      select_menu_option
    ;;
  esac
}

recreate_links() {
  clear
  SERVER_NAME=""
  input_server_name
  create_configs
  create_service
  tput civis
  echomsg "Restart service" 1
  systemctl daemon-reload >/dev/null 2>&1
  systemctl restart xray >/dev/null 2>&1
  echo -e "\n\033[1;32mLinks have been recreated\033[0m"
  echo -e "\n\033[0;36mXRay client linsks:\033[0m"
  cat "$path_client_links"
  echomsg "------------------------------------------------"
  read -n1 -r -p "Press any key to open menu..."
  tput cnorm
  show_connect_links
}

show_systemctl_status() {
  systemctl status xray --no-pager -l
  press_any_side_to_open_menu
}

show_journalctl_log() {
  journalctl -u xray -n 50 --no-pager
  press_any_side_to_open_menu
}

uninstall_xray() {
  tput civis
  (
    systemctl stop xray
    systemctl disable xray
    rm -f "$path_server_config"
    rm -f "$path_client_links"
    rm -f "$path_service"
    rm -f "$path_sysctl_config" 
    rm -f "$path_script"
    rm -f "$path_script_link" 
    rm -rf "$path_xray"
    rm -rf "$path_xray_dir"
    systemctl daemon-reload
    userdel xray
  ) >/dev/null 2>&1
  tput cnorm
}

accept_uninstall_xray() {
  echo
  read -rp "Uninstall application? [y/N]: " remove
  until [[ "$remove" =~ ^[yYnNдДнН]*$ ]]; do
    echo "Incorrect option"
    read -rp "Uninstall application? [y/N]: " remove
  done

  if [[ "$remove" =~ ^[yYдД]$ ]]; then
    echomsg "Uninstalling a program" 1
    uninstall_xray
    echook "Files and services deleted"
    exit 0
  else
    select_menu_option
  fi
}

install_xray() {
  clear
  check_root
  check_shell
  check_kernel
  check_os
  check_os_ver
  check_container
  show_header

  uninstall_xray

  read -n1 -r -p "Press any key to start installing..."

  install_pkgs
  check_443port
  input_server_name
  download_xray
  create_configs
  create_service
  add_user
  create_sysctl_config
  activate_xray

  mv "$(realpath "$0")" "$path_script"
  chmod +x "$path_script"
  ln -s "$path_script" "$path_script_link"

  echo -e "\n\033[1;32m🎉 Installation is completed\033[0m"
  echo -e "\n\033[0;36mXRay client linsks:\033[0m"
  cat "$path_client_links"
  press_any_side_to_open_menu
}

select_menu_option() {
  clear
  local menu

  show_header
  if systemctl is-active --quiet xray; then
    menu+="🟢 Active service\n"
    menu+="\nSelect option\n"
    menu+=" 1) ❌ Stop\n"
  else
    menu+="🔴 Service is not active\n"
    menu+="\nSelect option\n"
    menu+=" 1) 🚀 Start\n"
  fi

  menu+=" 2) 🌀 Restart\n 3) 🧿 Status\n 4) 🔗 Links\n 5) 📜 Log\n 6) 🪣 Uninstall\n 7) 🚪 Exit (Ctrl+C)"
  
  echo -e "$menu"

  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-8]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done

  [[ "$option" =~ ^[1-8]$ ]] && clear

  case "$option" in
    1)
      switch_active_service
    ;;
    2)
      restart_service
    ;;
    3)
      show_systemctl_status
    ;;
    4)
      show_connect_links
    ;;
    5)
      show_journalctl_log
    ;;
    6)
      accept_uninstall_xray
    ;;
    7)
      exit 0
    ;;
  esac
}

if [[ -f "$path_script" ]]; then
  select_menu_option
else
  install_xray
fi