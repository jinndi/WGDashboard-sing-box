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

SINGBOX="sing-box"

## Paths:
PATH_DIR="/opt/${SINGBOX}"
PATH_BIN="$PATH_DIR/bin/${SINGBOX}"
PATH_BIN_DIR="$(dirname "$PATH_BIN")"
PATH_ACME_DIR="$PATH_DIR/cert"
PATH_ENV_FILE="${PATH_DIR}/.env"
PATH_SERVICE="/etc/systemd/system/${SINGBOX}.service"
PATH_CONFIG_DIR="$PATH_DIR/configs"
PATH_TEMPLATE_DIR="$PATH_DIR/templates"
PATH_SYSCTL_CONF="/etc/sysctl.d/99-${SINGBOX}.conf"
PATH_SCRIPT="$PATH_DIR/${SINGBOX}"
PATH_SCRIPT_LINK="/usr/bin/${SINGBOX}"

if [[ -f "$PATH_ENV_FILE" ]]; then
  . "$PATH_ENV_FILE"
fi

## Version sing-box
# https://github.com/XTLS/Xray-core/releases
CUR_VERSION="1.12.9"
NEW_VERSION=""

if [[ -f "$PATH_BIN" ]]; then
  CUR_VERSION="$("$PATH_BIN" version | awk 'NR==1 {print $3}' | xargs)"
  NEW_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
  | grep -oP '"tag_name":\s*"\K[^"]+' \
  | sed 's/^v//')
fi

show_header() {
  echo -e "\033[1;35m"
  cat <<EOF
################################################
 SING-BOX SERVER $CUR_VERSION
 https://github.com/jinndi/WGDashboard-sing-box
################################################
EOF
  echo -e "\033[0m"
  [[ -n "$NEW_VERSION" && "$NEW_VERSION" != "$CUR_VERSION" ]] && \
    echo -e "\n\033[1;32mLatest version: $NEW_VERSION\033[0m\n"
}

echomsg(){ [ -n "$2" ] && echo >&2; echo -e "\033[1;34m$1\033[0m" >&2; }
echook(){ echo -e "\033[1;32m$1\033[0m" >&2; }
echoerr(){ echo -e "\033[1;31m$1\033[0m" >&2; }
exiterr(){ echo -e "\033[1;31mError: $1\033[0m" >&2; exit 1; }

check_root(){
  if [ "$(id -u)" != 0 ]; then
    exiterr "Installer must be launched on behalf of root 'sudo bash $0'"
  fi
}

check_shell(){
  if readlink /proc/$$/exe | grep -q "dash"; then
    exiterr "Installer must be launched using «bash», and not «sh»"
  fi
}

check_os(){
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
  fi
  if [ -n "$ID_LIKE" ] && echo "$ID_LIKE" | grep -iq "debian"; then
    return 0
  fi
  if [ "$ID" = "debian" ] || [ "$ID" = "ubuntu" ]; then
    return 0
  fi
  if [ -f /etc/debian_version ]; then
    return 0
  fi
  if command -v apt >/dev/null 2>&1; then
    return 0
  fi
  exiterr "Unsupported Linux distribution"
}

check_kernel(){
  if [[ $(uname -r | cut -d "." -f 1) -lt 5 ]]; then
    exiterr "For installation, nucleus OS version is necessary >= 5"
  fi
}

check_container(){
  if systemd-detect-virt -cq 2>/dev/null; then
    exiterr "Installation inside a container is not available"
  fi
}

check_IPv4(){
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

check_domain(){
  local d="$1"
  idn "$d" >/dev/null 2>&1 || return 1
  [[ $d =~ ^([a-zA-Z0-9]([a-z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$ ]] || return 1
  (( ${#d} <= 253 )) || return 1
  return 0
}

check_email(){
  if [[ ! "$1" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echoerr "Incorrect email format"
    return 1
  fi
  return 0
}

check_port() {
  local port="$1"
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echoerr "Incorrect port range (1-65535)"
    return 1
  fi
  if lsof -i :"$port" >/dev/null ; then
    echoerr "Port $port is busy"
    return 1
  fi
  return 0
}

wait_for_apt_unlock(){
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

install_pkgs(){
  tput civis
  wait_for_apt_unlock
  local cmds=(
    "apt-get -yqq update"
    "apt-get -yqq upgrade"
    "apt-get -yqq install iproute2 iptables idn jq openssl lsof tar gzip"
  )
  local cmd status
  echomsg "Updating packages and installing dependencies..." 1
  for cmd in "${cmds[@]}"; do
    echo " > $cmd"
    eval "$cmd" > /dev/null 2>&1
    status=$?
    [[ $status -ne 0 ]] && exiterr "'$cmd' failed"
  done
  tput cnorm
}

set_env_var(){
  local var value
  var="$1"
  value="$2"
  if [[ ! -f "$PATH_ENV_FILE" ]]; then
    mkdir -p "$(dirname "$PATH_ENV_FILE")"
    touch "$PATH_ENV_FILE"
  fi
  value="$(echo "$value" | tr '[:upper:]' '[:lower:]')"
  if grep -q "^${var}=" "$PATH_ENV_FILE"; then
    sed -i "s|^${var}=.*|${var}=${value}|" "$PATH_ENV_FILE"
  else
    echo "${var}=${value}" >> "$PATH_ENV_FILE"
  fi
}

input_masking_domain(){
  local mask_domain
  echomsg "Enter the masking domain or select from the suggested options:" 1
  echo -e " 1) github.com\n 2) microsoft.com\n 3) samsung.com\n 4) nvidia.com\n 5) amd.com"
  read -rp " > " option
  until [[ "$option" =~ ^[1-5]$  ]] || check_domain "$option"; do
    echoerr "Incorrect option"
    read -rp " > " option
  done
  case "$option" in
    1) mask_domain="github.com";;
    2) mask_domain="microsoft.com";;
    3) mask_domain="samsung.com";;
    4) mask_domain="nvidia.com";;
    5) mask_domain="amd.com";;
    *) mask_domain="$option";;
  esac
  set_env_var "MASK_DOMAIN" "$mask_domain"
}

input_acme_domain(){
  local acme_domain
  is_acme_domain=0
  while true; do
    echomsg "Enter the domain name of this server for the SSL certificate:\n(Press Enter key to set later)" 1
    read -e -i "$ACME_DOMAIN" -rp " > " acme_domain
    if [[ -z "$acme_domain" ]]; then
      break
    else
      if check_domain "$acme_domain"; then
        set_env_var "ACME_DOMAIN" "$acme_domain"
        is_acme_domain=1
        break
      else
        echoerr "Incorrect domain format"
      fi
    fi
  done
}

input_acme_email(){
  [[ "$is_acme_domain" -eq 0 ]] && return 0
  local acme_email
  while true; do
    echomsg "Enter your email address for the SSL certificate:" 1
    read -e -i "$ACME_EMAIL" -rp " > " acme_email
    if check_email "$acme_email"; then
      set_env_var "ACME_EMAIL" "$acme_email"
      break
    fi
  done
}

input_acme_provider(){
  [[ "$is_acme_domain" -eq 0 ]] && return 0
  local acme_provider
  echomsg "Enter ACME provider or select from the suggested options:" 1
  echo -e " 1) letsencrypt\n 2) zerossl"
  read -e -i "$ACME_PROVIDER" -rp " > " option
  until [[ "$option" =~ ^[1-2]$  || -n "$option" ]] ; do
    echoerr "Incorrect option"
    read -e -i "$ACME_PROVIDER" -rp " > " option
  done
  case "$option" in
    1) acme_provider="letsencrypt";;
    2) acme_provider="zerossl";;
    *) acme_provider="$option";;
  esac
  set_env_var "ACME_PROVIDER" "$acme_provider"
}

input_listen_port(){
  local listen_port
  while true; do
    echomsg "Enter the port number for the VPN service:" 1
    read -rp " > " listen_port
    if check_port "$listen_port"; then
      set_env_var "LISTEN_PORT" "$listen_port"
      break
    fi
  done
}

set_public_ip(){
  local public_ip
  public_ip="$(curl -4 -s ip.sb)"
  [ -z "$public_ip" ] && public_ip="$(curl -4 -s ifconfig.me)"
  [ -z "$public_ip" ] && public_ip="$(curl -4 -s https://api.ipify.org)"
  if ! check_IPv4 "$public_ip" >/dev/null 2>&1; then
    echoerr "Failed to determine the public IP"
    while true; do
      echomsg "Enter IPv4 address of this server" 1
      read -rp " > " public_ip
      if check_IPv4 "$public_ip"; then break; fi
    done
  fi
  set_env_var "PUBLIC_IP" "$public_ip"
}

download_singbox(){
  tput civis
  echomsg "Downloading sing-box version $CUR_VERSION..." 1
  mkdir -p "$PATH_BIN_DIR" || exiterr "mkdir PATH_BIN_DIR failed"
  curl -fsSL -o sin-box.tar.gz \
    "https://github.com/SagerNet/sing-box/releases/download/v${CUR_VERSION}/sing-box-${CUR_VERSION}-linux-amd64.tar.gz" \
    || exiterr "sing-box curl download failed"
  tar -xzf sin-box.tar.gz -C "$PATH_BIN_DIR" --strip-components=1 > /dev/null \
    || exiterr "sing-box failed to extract archive"
  chmod +x "$PATH_BIN" > /dev/null 2>&1 || exiterr "sing-box chmod failed"
  rm -f ./sin-box.tar.gz > /dev/null 2>&1 || exiterr "sing-box rm failed"
  tput cnorm
}

create_sysctl_config(){
  echomsg "Creating network settings..." 1
  mkdir -p "$(dirname "$PATH_SYSCTL_CONF")"
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
  } > "$PATH_SYSCTL_CONF"
  if modprobe -q tcp_bbr && [ -f /proc/sys/net/ipv4/tcp_congestion_control ]
  then
    {
      echo "net.core.default_qdisc = fq"
      echo "net.ipv4.tcp_congestion_control = bbr"
    } >> "$PATH_SYSCTL_CONF"
  else
    if modprobe -q tcp_hybla && [ -f /proc/sys/net/ipv4/tcp_congestion_control ]
    then
      echo "net.ipv4.tcp_congestion_control = hybla" >> "$PATH_SYSCTL_CONF"
    fi
  fi
  sysctl -e -q -p "$PATH_SYSCTL_CONF"
}

generate_credentials(){
  local psk keys uuid pvk pbk sid
  echomsg "Generating credentials..." 1
  psk="$(openssl rand -base64 16)" || exiterr "Failed to generate password"
  uuid=$("$PATH_BIN" generate uuid) || exiterr "Failed to generate UUID"
  keys=$("$PATH_BIN" generate reality-keypair) || exiterr "Failed to generate reality keys"
  pvk=$(echo "$keys" | grep 'PrivateKey' | awk '{print $NF}') || exiterr "Failed to extract reality private key"
  pbk=$(echo "$keys" | grep 'PublicKey' | awk '{print $NF}') || exiterr "Failed to extract reality public key"
  sid=$(openssl rand -hex 3) || exiterr "Failed to generate reality short id"
  set_env_var "PSK" "$psk"
  set_env_var "UUID" "$uuid"
  set_env_var "PVK" "$pvk"
  set_env_var "PBK" "$pbk"
  set_env_var "SID" "$sid"
}

create_base_config(){
  cat > "$PATH_CONFIG_DIR/base.json" <<EOF_BASE
{
  "log": {
    "level": "fatal",
    "timestamp": true
  },
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "ip_is_private": true,
        "action": "reject"
      }
    ],
    "final": "direct"
   }
}
EOF_BASE
}

create_ss2022_tcp_multiplex_templates(){
  local tag base_path psk base64_part
  local method="2022-blake3-aes-128-gcm"
  tag="Shadowsocks2022-TCP-Multiplex"
  base_path="${PATH_TEMPLATE_DIR}/${tag}"
  cat > "${base_path}.template" <<EOF_SS2022_MULTIPLEX
{
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "${tag}",
      "listen": "::",
      "listen_port": <LISTEN_PORT>,
      "network": "tcp",
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "method": "${method}",
      "password": <PSK>,
      "multiplex": {
        "enabled": true
      }
    }
  ]
}
EOF_SS2022_MULTIPLEX
  echo "echo \"ss://${method}:\${PSK}@\${PUBLIC_IP}:\${LISTEN_PORT}?type=tcp&multiplex=h2mux\"" \
  > "${base_path}.link"
}

create_vless_reality_vision_templates(){
  local tag base_path
  tag="VLESS-TCP-XTLS-Vision-REALITY"
  base_path="${PATH_TEMPLATE_DIR}/${tag}"
  cat > "${base_path}.template" <<EOF_VLESS_REALITY_VISION
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "${tag}",
      "listen": "::",
      "listen_port": <LISTEN_PORT>,
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "users": [{
        "uuid": "<UUID>",
        "flow": "xtls-rprx-vision"
      }],
      "tls": {
        "enabled": true,
        "server_name": "<MASK_DOMAIN>",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "<MASK_DOMAIN>",
            "server_port": 443
          },
          "private_key": "<PVK>",
          "short_id": ["<SID>"]
        }
      }
    }
  ]
}
EOF_VLESS_REALITY_VISION
  echo "echo \"vless://\${UUID}@\${PUBLIC_IP}:\${LISTEN_PORT}?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&pbk=\${PBK}&sid=\${SID}&sni=\${MASK_DOMAIN}&alpn=h2&fp=chrome\"" \
  > "${base_path}.link"
}

create_vless_tls_vision_templates(){
  local tag base_path
  tag="VLESS-TCP-XTLS-Vision"
  base_path="${PATH_TEMPLATE_DIR}/${tag}"
  cat > "${base_path}.template" <<EOF_VLESS_TLS_VISION
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "${tag}",
      "listen": "::",
      "listen_port": <LISTEN_PORT>,
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "users": [{
        "uuid": "<UUID>",
        "flow": "xtls-rprx-vision"
      }],
      "tls": {
        "enabled": true,
        "server_name": "<ACME_DOMAIN>",
        "alpn": ["h2"],
        "acme": {
          "domain": "<ACME_DOMAIN>",
          "email": "<ACME_EMAIL>",
          "provider": "<ACME_PROVIDER>",
          "data_directory": "<PATH_ACME_DIR>"
        }
      }
    }
  ]
}
EOF_VLESS_TLS_VISION
  echo "echo \"vless://\${UUID}@\${PUBLIC_IP}:\${LISTEN_PORT}?type=tcp&security=tls&encryption=none&flow=xtls-rprx-vision&sni=\${ACME_DOMAIN}&alpn=h2&fp=chrome\"" \
  > "${base_path}.link"
}

create_hysteria2_templates(){
  local tag base_path
  tag="Hysteria2"
  base_path="${PATH_TEMPLATE_DIR}/${tag}"
  cat > "${base_path}.template" <<EOF_HY2
{
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "${tag}",
      "listen": "::",
      "listen_port": <LISTEN_PORT>,
      "users": [{
        "password": "<PSK>"
      }],
      "masquerade": "https://<MASK_DOMAIN>",
      "tls": {
         "enabled": true,
         "server_name": "<ACME_DOMAIN>",
         "alpn": ["h3"],
         "acme": {
            "domain": "<ACME_DOMAIN>",
            "email": "<ACME_EMAIL>",
            "provider": "<ACME_PROVIDER>",
            "data_directory": "<PATH_ACME_DIR>"
          }
       }
    }
  ]
}
EOF_HY2
  echo "hy2://\${PSK}@\${PUBLIC_IP}:\${LISTEN_PORT}?sni=\${ACME_DOMAIN}&alpn=h3&insecure=0&obfs=none" \
  > "${base_path}.link"
}

apply_template(){
  local name="$1"
  local template="${PATH_TEMPLATE_DIR}/${name}.template"
  local config="${PATH_CONFIG_DIR}/inbound.json"
  . "$PATH_ENV_FILE"
  cp -f "$template" "$config"
  sed -i \
    -e "s|<LISTEN_PORT>|${LISTEN_PORT}|g" \
    -e "s|<PSK>|${PSK}|g" \
    -e "s|<UUID>|${UUID}|g" \
    -e "s|<PVK>|${PVK}|g" \
    -e "s|<PBK>|${PBK}|g" \
    -e "s|<SID>|${SID}|g" \
    -e "s|<MASK_DOMAIN>|${MASK_DOMAIN}|g" \
    -e "s|<ACME_DOMAIN>|${ACME_DOMAIN}|g" \
    -e "s|<ACME_EMAIL>|${ACME_EMAIL}|g" \
    -e "s|<ACME_PROVIDER>|${ACME_PROVIDER}|g" \
    -e "s|<PATH_ACME_DIR>|${PATH_ACME_DIR}|g" \
    "$config"
  set_env_var "ACTIVE_INBOUND" "$name"
}

create_configs(){
  echomsg "Creating sing-box configurations..." 1
  mkdir -p "$PATH_CONFIG_DIR" "$PATH_TEMPLATE_DIR" "$PATH_ACME_DIR"
  create_base_config
  create_ss2022_tcp_multiplex_templates
  create_vless_reality_vision_templates
  if [[ "$is_acme_domain" -eq 1 ]]; then
    create_vless_tls_vision_templates
    create_hysteria2_templates
  fi
  apply_template "VLESS-TCP-XTLS-Vision-REALITY"
}

create_service(){
  local iptables_path
  echomsg "Creating systemd service..." 1
  iptables_path=$(command -v iptables)
  if [[ $(systemd-detect-virt) == "openvz" ]] && \
    readlink -f "$(command -v iptables)" | grep -q "nft" && \
    hash iptables-legacy 2>/dev/null
  then
    iptables_path=$(command -v iptables-legacy)
  fi
  {
    echo "[Unit]"
    echo "Description=${SINGBOX} server ${CUR_VERSION}"
    echo "Documentation=https://sing-box.sagernet.org"
    echo "After=network.target nss-lookup.target network-online.target"
    echo
    echo "[Service]"
    echo "User=${SINGBOX}"
    echo "Group=${SINGBOX}"
    echo "EnvironmentFile=${PATH_ENV_FILE}"
    echo "ReadWritePaths=${PATH_ACME_DIR}"
    echo "ProtectSystem=full"
    echo "ProtectHome=yes"
    echo "NoNewPrivileges=yes"
    echo "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH"
    echo "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH"
    echo "PermissionsStartOnly=true"
    echo "ExecStartPre=${iptables_path} -I INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT"
    echo "ExecStartPre=${iptables_path} -I INPUT -p tcp --dport \$LISTEN_PORT -j ACCEPT"
    echo "ExecStartPre=${iptables_path} -I INPUT -p udp --dport \$LISTEN_PORT -j ACCEPT"
    echo "ExecStart=${PATH_BIN} -C ${PATH_CONFIG_DIR} run"
    echo "ExecReload=/bin/kill -HUP \$MAINPID"
    echo "ExecStartPre=${iptables_path} -D INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT"
    echo "ExecStopPost=${iptables_path} -D INPUT -p tcp --dport \$LISTEN_PORT -j ACCEPT"
    echo "ExecStopPost=${iptables_path} -D INPUT -p udp --dport \$LISTEN_PORT -j ACCEPT"
    echo "Restart=on-failure"
    echo "RestartSec=10s"
    echo "LimitNOFILE=51200"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > "$PATH_SERVICE"
}

add_user(){
  echomsg "Adding user '${SINGBOX}'..." 1
  if ! id -u "${SINGBOX}" >/dev/null 2>&1; then
    useradd --system --user-group \
      --home-dir /nonexistent \
      --no-create-home \
      --shell /usr/sbin/nologin \
      "${SINGBOX}" >/dev/null 2>&1 || exiterr "'useradd ${SINGBOX}' failed"
    chown ${SINGBOX}:${SINGBOX} "$PATH_ACME_DIR"
    chmod 750 "$PATH_ACME_DIR"
  fi
}

switch_protocol(){
  local protocols options option name
  shopt -s nullglob
  protocols=( "$PATH_TEMPLATE_DIR"/*.template )
  shopt -u nullglob
  [[ ${#protocols[@]} -eq 0 ]] && exiterr "No protocols available"
  echomsg "Select the protocol to be used by default:" 1
  options=""
  for i in "${!protocols[@]}"; do
    options+=" $((i+1))) $(basename "${protocols[i]}") \n"
  done
  echo -e "$options"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-${#protocols[@]}]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
  clear
  echomsg "Setting the active protocol..." 1
  name="$(basename "${protocols[option-1]}")"
  apply_template "$name"
  if systemctl is-active --quiet "${SINGBOX}"; then
    systemctl restart ${SINGBOX} --wait >/dev/null 2>&1
  fi
  echook "The active protocol is set to '$name'"
  press_any_side_to_open_menu
}

change_listen_port(){
  local listen_port
  while true; do
    echomsg "Enter the new port number for the VPN service:" 1
    read -e -i "$LISTEN_PORT" -rp " > " listen_port
    if check_port "$listen_port"; then
      break
    fi
  done
  echomsg "Setting the new port..." 1
  set_env_var "LISTEN_PORT" "$listen_port"
  apply_template "$ACTIVE_INBOUND"
  if systemctl is-active --quiet "${SINGBOX}"; then
    systemctl restart ${SINGBOX} --wait >/dev/null 2>&1
  fi
  echook "The new port is set to ${listen_port}"
  press_any_side_to_open_menu
}

change_acme_settings(){
  input_acme_domain
  if [[ "$is_acme_domain" -eq 1 ]]; then
    input_acme_email
    input_acme_provider
    create_vless_tls_vision_templates
    create_hysteria2_templates
    if systemctl is-active --quiet "${SINGBOX}"; then
      systemctl restart ${SINGBOX} --wait >/dev/null 2>&1
    fi
    echook "ACME configuration completed"
    read -n1 -r -p "Press any key to back menu..."
  fi
  show_ssl_settings
}

change_masking_domain(){
  input_masking_domain
  if systemctl is-active --quiet "${SINGBOX}"; then
    systemctl restart ${SINGBOX} --wait >/dev/null 2>&1
  fi
  echook "Mask domain has been changed"
  read -n1 -r -p "Press any key to back menu..."
  show_ssl_settings
}

show_ssl_settings(){
  local menu=""
  clear
  show_header
  . "$PATH_ENV_FILE"
  if [[ -n "$ACME_DOMAIN" && -n "$ACME_EMAIL" ]]; then
    menu+="\033[0;36mDomain:\033[0m${ACME_DOMAIN}"
    menu+="\033[0;36mE-mail:\033[0m${ACME_EMAIL}"
    menu+="\033[0;36mProvider:\033[0m${ACME_PROVIDER}"
    menu+="---------------------------------------------"
    menu+="\033[0;36mMask domain:\033[0m${MASK_DOMAIN}"
    menu+="\nSelect option:"
    menu+=" 1) 🌍 Change ACME settings\n"
  else
    menu+="\033[0;31mACME not configured\033[0m"
    menu+="---------------------------------------------"
    menu+="\033[0;36mMask domain:\033[0m${MASK_DOMAIN}"
    menu+="\nSelect option:"
    menu+=" 1) 🌍 Configure ACME Certificates\n"
  fi
  menu+=" 2) 🎭 Change the masking domain\n"
  echo -e "$menu 2) 📖 Back menu"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-3]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
  case "$option" in
    1) change_acme_settings;;
    2) change_masking_domain;;
    3) select_menu_option;;
  esac
}

start_service(){
  tput civis
  local timeout=10
  systemctl daemon-reload >/dev/null 2>&1
  echomsg "Starting service..." 1
  systemctl enable "${SINGBOX}" >/dev/null 2>&1
  systemctl start "${SINGBOX}" --wait >/dev/null 2>&1
  timeout=10
  while ! systemctl is-active --quiet "${SINGBOX}" && [ $timeout -gt 0 ]; do
    sleep 1
    ((timeout--))
  done
  if systemctl is-active --quiet "${SINGBOX}"; then
    echook "Service launched successfully"
  else
    echoerr "Failed to launch the service"
  fi
  tput cnorm
}

stop_service(){
  tput civis
  local timeout=10
  echomsg "Stopping service..." 1
  systemctl disable "${SINGBOX}" >/dev/null 2>&1
  systemctl stop "${SINGBOX}" --wait >/dev/null 2>&1
  while systemctl is-active --quiet "${SINGBOX}" && [ $timeout -gt 0 ]; do
    sleep 1
    ((timeout--))
  done
  if systemctl is-active --quiet "${SINGBOX}"; then
    echoerr "Failed to stop the service"
  else
    echook "Service stopped successfully"
  fi
  tput cnorm
}

press_any_side_to_open_menu(){
  echomsg "------------------------------------------------"
  read -n1 -r -p "Press any key to open menu..."
  select_menu_option
}

restart_service() {
  tput civis
  local timeout=10
  echomsg "Restarting service..." 1
  systemctl daemon-reload >/dev/null 2>&1
  systemctl restart "${SINGBOX}" --wait >/dev/null 2>&1
  while ! systemctl is-active --quiet "${SINGBOX}" && [ $timeout -gt 0 ]; do
    sleep 1
    ((timeout--))
  done
  if systemctl is-active --quiet "${SINGBOX}"; then
    echook "Service ${SINGBOX} is successfully restarted"
  else
    echoerr "Failed to restart service ${SINGBOX}"
  fi
  tput cnorm
  press_any_side_to_open_menu
}

switch_active_service(){
  if systemctl is-active --quiet "${SINGBOX}"; then
    start_service
  else
    stop_service
  fi
  press_any_side_to_open_menu
}

echo_connect_link(){
  local path_link
  path_link="$PATH_TEMPLATE_DIR/${ACTIVE_INBOUND}.link"
  [[ -f "$path_link" ]] || exiterr "Link file not found"
  . "$path_link"
}

recreate_link(){
  clear
  echomsg "Recreating connection link..." 1
  generate_credentials
  . "$PATH_ENV_FILE"
  echomsg "Restarting service..." 1
  systemctl restart "${SINGBOX}" --wait >/dev/null 2>&1
  echook "The connection link has been recreated"
  read -n1 -r -p "Press any key to view the new link..."
  show_connect_link
}

show_connect_link(){
  clear
  show_header
  echo -e "\033[0;36mClient link:\033[0m"
  echo_connect_link
  echo -e "\nSelect option:"
  echo -e " 1) 🔑 Recreate\n 2) 📖 Back menu"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-2]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
  case "$option" in
    1) recreate_link;;
    2) select_menu_option;;
  esac
}

show_systemctl_status(){
  systemctl status "${SINGBOX}" --no-pager -l
  press_any_side_to_open_menu
}

show_journalctl_log(){
  journalctl -u "${SINGBOX}" -n 50 --no-pager
  press_any_side_to_open_menu
}

uninstall(){
  (
    systemctl stop "${SINGBOX}" --wait
    systemctl disable "${SINGBOX}"
    rm -rf "$PATH_CONFIG_DIR"
    rm -rf "$PATH_ACME_DIR"
    rm -rf "$PATH_TEMPLATE_DIR"
    rm -f "$PATH_ENV_FILE"
    rm -f "$PATH_SERVICE"
    rm -f "$PATH_SYSCTL_CONF"
    rm -f "$PATH_SCRIPT"
    rm -f "$PATH_SCRIPT_LINK"
    rm -rf "$PATH_BIN_DIR"
    rm -rf "$PATH_DIR"
    systemctl daemon-reload
    userdel "${SINGBOX}"
  ) >/dev/null 2>&1
}

accept_uninstall(){
  echo
  read -rp "Uninstall application? [y/n]: " remove
  until [[ "$remove" =~ ^[yYnN]*$ ]]; do
    echo "Incorrect option"
    read -rp "Uninstall application? [y/n]: " remove
  done
  if [[ "$remove" =~ ^[yY]$ ]]; then
    echomsg "Uninstalling a program..." 1
    uninstall
    echook "Files and services deleted"
    exit 0
  else
    select_menu_option
  fi
}

install(){
  clear
  check_root
  check_shell
  check_kernel
  check_os
  check_container
  show_header
  read -n1 -r -p "Press any key to start installing..."
  uninstall
  install_pkgs
  input_masking_domain
  input_acme_domain
  input_acme_email
  input_acme_provider
  input_listen_port
  set_public_ip
  download_singbox
  create_sysctl_config
  generate_credentials
  create_configs
  create_service
  add_user
  mkdir -p "$(dirname "$PATH_SCRIPT")"
  curl -fsSL -o "$PATH_SCRIPT" \
    "https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/dev/scripts/sing-box-server-install.sh" \
    || exiterr "Failed to download the management script"
  chmod +x "$PATH_SCRIPT"
  ln -s "$PATH_SCRIPT" "$PATH_SCRIPT_LINK"
  echo -e "\n\033[1;32m🎉 Installation is completed\033[0m"
  press_any_side_to_open_menu
}

select_menu_option(){
  clear
  local menu
  show_header
  if systemctl is-active --quiet sing-box; then
    menu+="🟢 Active service\n"
    menu+="\nSelect option\n"
    menu+=" 1) ❌ Stop service\n"
  else
    menu+="🔴 Service is not active\n"
    menu+="\nSelect option\n"
    menu+=" 1) 🚀 Start service\n"
  fi
  menu+=" 2) 🌀 Restart service\n 3) 🧿 Status service\n"
  menu+=" 4) 🔗 Connection link\n 5) ✨ Change protocol\n"
  menu+=" 6) 🔌 Change port\n 7) 🌐 SSL settings\n"
  menu+=" 8) 📜 Last logs\n 9) 🪣 Uninstall\n"
  menu+=" Ctrl+C) 🚪 Exit"
  echo -e "$menu"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-9]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
  [[ "$option" =~ ^[1-9]$ ]] && clear
  case "$option" in
    1) switch_active_service;;
    2) restart_service;;
    3) show_systemctl_status;;
    4) show_connect_link;;
    5) switch_protocol;;
    6) change_listen_port;;
    7) show_ssl_settings;;
    8) show_journalctl_log;;
    9) accept_uninstall;;
  esac
}

if [[ -f "$PATH_SCRIPT" ]]; then
  select_menu_option
else
  install
fi
