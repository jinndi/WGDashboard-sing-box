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

## Service name
SINGBOX="sing-box"

## Paths:
PATH_DIR="/opt/${SINGBOX}"
PATH_BIN="${PATH_DIR}/bin/${SINGBOX}"
PATH_BIN_DIR="$(dirname "$PATH_BIN")"
PATH_ACME_DIR="/etc/ssl/certmagic"
PATH_ENV_FILE="${PATH_DIR}/.env"
PATH_SERVICE="/etc/systemd/system/${SINGBOX}.service"
PATH_CONFIG_DIR="${PATH_DIR}/configs"
PATH_INBOUND="${PATH_CONFIG_DIR}/inbound.json"
PATH_CLIENT_LINK="${PATH_DIR}/client.link"
PATH_SYSCTL_CONF="/etc/sysctl.d/99-${SINGBOX}.conf"
PATH_SCRIPT="${PATH_DIR}/${SINGBOX}"
PATH_SCRIPT_LINK="/usr/bin/${SINGBOX}"

INBOUNDS=(
  "Shadowsocks2022-TCP-UDP"
  "Shadowsocks2022-TCP-Multiplex"
  "VLESS-TCP-XTLS-Vision-REALITY"
  "WireGuard"
)

INBOUNDS_SSL=(
  "VLESS-TCP-XTLS-Vision"
  "VLESS-TCP-TLS-Multiplex"
  "Trojan-TCP-TLS"
  "Trojan-TCP-TLS-Multiplex"
  "Hysteria2"
  "TUIC"
)

if [[ -f "$PATH_ENV_FILE" ]]; then
  . "$PATH_ENV_FILE"
fi

## Version sing-box
# https://github.com/XTLS/Xray-core/releases
CUR_VERSION="1.12.11"
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
}

cyan()    { echo -e "\033[36m$1\033[0m"; }
red()     { echo -e "\033[31m$1\033[0m"; }
green()   { echo -e "\033[32m$1\033[0m"; }

echomsg() { [ -n "$2" ] && echo >&2; cyan "$1" >&2; }
echook()  { green "$1" >&2; }
echoerr() { red "$1" >&2; }
exiterr() { red "$1" >&2; exit 1; }

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

check_tls13() {
  local domain="$1"
  local output
  output=$(echo | openssl s_client -connect "${domain}:443" -tls1_3 2>&1)
  if echo "$output" | grep -Eq "TLSv1\.3"; then
    return 0
  fi
  return 1
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
  if [[ -z "$port" ]]; then
    echoerr "Specify a port from 1 to 65535"
    return 1
  fi
  if [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
    echoerr "Incorrect port range (1-65535)"
    return 1
  fi
  if lsof -i :"$port" >/dev/null ; then
    echoerr "Port $port is busy"
    return 1
  fi
  return 0
}

check_certificate(){
  local cert_file="$1"
  if [[ ! -f "$cert_file" ]]; then
    echoerr "Certificate not found: $cert_file"
    return 1
  fi
  if ! openssl x509 -in "$cert_file" -noout &>/dev/null; then
    echoerr "The file is not a valid X.509 certificate."
    return 1
  fi
  local end_date
  end_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
  local end_ts now_ts
  end_ts=$(date -d "$end_date" +%s)
  now_ts=$(date +%s)
  if (( now_ts > end_ts )); then
    echoerr "Certificate has expired ($end_date)"
    return 1
  fi
  return 0
}

check_private_key() {
  local cert_file="$1"
  local key_file="$2"
  if [[ ! -f "$key_file" ]]; then
    echoerr "Private key not found: $key_file"
    return 1
  fi
  local cert_pub key_pub
  cert_pub=$(openssl x509 -in "$cert_file" -noout -pubkey 2>/dev/null)
  key_pub=$(openssl pkey -in "$key_file" -pubout 2>/dev/null)
  if [[ "$cert_pub" != "$key_pub" ]]; then
    echoerr "Private key does NOT match the certificate"
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
}

set_env_var(){
  local var value
  var="$1"
  value="$2"
  if [[ ! -f "$PATH_ENV_FILE" ]]; then
    mkdir -p "$(dirname "$PATH_ENV_FILE")"
    touch "$PATH_ENV_FILE"
  fi
  if grep -q "^${var}=" "$PATH_ENV_FILE"; then
    sed -i "s|^${var}=.*|${var}=${value}|" "$PATH_ENV_FILE"
  else
    echo "${var}=${value}" >> "$PATH_ENV_FILE"
  fi
}

input_masking_domain(){
  local menu mask_domain
  echomsg "Enter the masking domain or select from the suggested options:" 1
  menu+=" $(green "1.") github.com\n"
  menu+=" $(green "2.") microsoft.com\n"
  menu+=" $(green "3.") yahoo.com.com\n"
  menu+=" $(green "4.") speed.cloudflare.com\n"
  menu+=" $(green "5.") amd.com"
  echo -e "$menu"
  read -rp " > " option
  until [[ "$option" =~ ^[1-5]$ ]] || ( check_domain "$option" && check_tls13 "$option" ); do
    echoerr "Incorrect option (1-5), or invalid TLSv1.3 domain"
    read -rp " > " option
  done
  case "$option" in
    1) mask_domain="github.com";;
    2) mask_domain="microsoft.com";;
    3) mask_domain="yahoo.com.com";;
    4) mask_domain="speed.cloudflare.com";;
    5) mask_domain="amd.com";;
    *) mask_domain="$option";;
  esac
  set_env_var "MASK_DOMAIN" "$mask_domain"
}

input_acme_domain(){
  local is_path_cert="${1:-0}"
  while true; do
    if [[ "$is_path_cert" -eq 1 ]]; then
      echomsg "Enter the certificate’s domain name:" 1
    else
      echomsg "Enter the domain name of this server for the SSL certificate:" 1
    fi
    read -e -i "$ACME_DOMAIN" -rp " > " acme_domain
    if check_domain "$acme_domain"; then
      set_env_var "ACME_DOMAIN" "$acme_domain"
      break
    else
      echoerr "Incorrect domain format"
    fi
  done
}

input_acme_email(){
  local acme_email
  while true; do
    echomsg "Enter your email for ACME account registration:" 1
    read -e -i "$ACME_EMAIL" -rp " > " acme_email
    if check_email "$acme_email"; then
      set_env_var "ACME_EMAIL" "$acme_email"
      break
    else
      echoerr "Incorrect email format"
    fi
  done
}

input_cloudflare_api_token(){
  echomsg "Enter your Cloudflare API token:\nhttps://dash.cloudflare.com/profile/api-tokens" 1
  read -e -i "$CLOUDFLARE_API_TOKEN" -rp " > " api_token
  until [[ -n "$api_token" ]] ; do
    echoerr "Incorrect token"
    read -e -i "$CLOUDFLARE_API_TOKEN" -rp " > " api_token
  done
  set_env_var "CLOUDFLARE_API_TOKEN" "$api_token"
}

input_zerossl_eab(){
  echomsg "Enter ZeroSSL EAB KID:\nhttps://app.zerossl.com/developer" 1
  read -e -i "$ZEROSSL_EAB_KID" -rp " > " key_id
  until [[ -n "$key_id" ]] ; do
    echoerr "Incorrect token"
    read -e -i "$ZEROSSL_EAB_KID" -rp " > " key_id
  done
  set_env_var "ZEROSSL_EAB_KID" "$key_id"
  echomsg "Enter ZeroSSL EAB HMAC Key:\nhttps://app.zerossl.com/developer" 1
  read -e -i "$ZEROSSL_EAB_HMAC_KEY" -rp " > " mac_key
  until [[ -n "$key_id" ]] ; do
    echoerr "Incorrect token"
    read -e -i "$ZEROSSL_EAB_HMAC_KEY" -rp " > " mac_key
  done
  set_env_var "ZEROSSL_EAB_HMAC_KEY" "$mac_key"
}

input_path_existing_cert(){
  echomsg "Enter path to server SSL certificate chain:" 1
  read -e -i "$SSL_CERTIFICATE_PATH" -rp " > " certificate_path
  until check_certificate "$certificate_path"; do
    read -e -i "$SSL_CERTIFICATE_PATH" -rp " > " certificate_path
  done
  set_env_var "SSL_CERTIFICATE_PATH" "$certificate_path"
  echomsg "Enter path to the server SSL private key:" 1
  read -e -i "$SSL_KEY_PATH" -rp " > " key_path
  until check_private_key "$certificate_path" "$key_path"; do
    read -e -i "$SSL_KEY_PATH" -rp " > " key_path
  done
  set_env_var "SSL_KEY_PATH" "$key_path"
}

input_acme_provider(){
  local menu is_acme_completed=0
  echomsg "Select ACME provider, or path to existing SSL certificates:" 1
  menu+=" $(green "1.") Let's Encrypt HTTP-01 challenge (ports 80 and 443 should be free)\n"
  menu+=" $(green "2.") Let's Encrypt DNS-01 (need Cloudflare API token)\n"
  menu+=" $(green "3.") ZeroSSL HTTP-01 challenge (ports 80 and 443 should be free + need EAB Credentials)\n"
  menu+=" $(green "4.") ZeroSSL DNS-01 challenge (need EAB Credentials + Cloudflare API token)\n"
  menu+=" $(green "5.") Set local path to existing certificates\n"
  menu+=" $(green "6.") Configure later"
  echo -e "$menu"
  read -e -rp " > " option
  until [[ "$option" =~ ^[1-6]$ ]] ; do
    echoerr "Incorrect option"
    read -e -rp " > " option
  done
  case "$option" in
    1)
      input_acme_domain
      input_acme_email
      set_env_var "SSL_TYPE" "letsencrypt-http01"
      set_env_var "ACME_PROVIDER" "letsencrypt"
    ;;
    2)
      input_acme_domain
      input_acme_email
      input_cloudflare_api_token
      set_env_var "SSL_TYPE" "letsencrypt-dns01-cloudflare"
      set_env_var "ACME_PROVIDER" "letsencrypt"
      set_env_var "DNS01_PROVIDER" "cloudflare"
    ;;
    3)
      input_acme_domain
      input_acme_email
      input_zerossl_eab
      set_env_var "SSL_TYPE" "zerossl-http01"
      set_env_var "ACME_PROVIDER" "zerossl"
    ;;
    4)
      input_acme_domain
      input_acme_email
      input_zerossl_eab
      input_cloudflare_api_token
      set_env_var "SSL_TYPE" "zerossl-dns01-cloudflare"
      set_env_var "ACME_PROVIDER" "zerossl"
      set_env_var "DNS01_PROVIDER" "cloudflare"
    ;;
    5)
      input_acme_domain 1
      input_path_existing_cert
      set_env_var "SSL_TYPE" "path-ssl"
      set_env_var "ACME_PROVIDER" ""
    ;;
  esac
  [[ "$option" =~ ^[1-5]$ ]] && is_acme_completed=1
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
  local ver="${1:-$CUR_VERSION}"
  echomsg "Downloading sing-box version ${ver}..." 1
  mkdir -p "$PATH_BIN_DIR" || exiterr "mkdir PATH_BIN_DIR failed"
  curl -fsSL -o /tmp/sin-box.tar.gz \
    "https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-amd64.tar.gz" \
    || exiterr "sing-box curl download failed"
  tar -xzf /tmp/sin-box.tar.gz -C "$PATH_BIN_DIR" --strip-components=1 > /dev/null \
    || exiterr "sing-box failed to extract archive"
  chmod +x "$PATH_BIN" > /dev/null 2>&1 || exiterr "sing-box chmod failed"
  rm -f /tmp/sin-box.tar.gz > /dev/null 2>&1 || exiterr "sing-box rm failed"
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
  local psk uuid vless_keys vless_pvk vless_pbk vless_sid
  local wg_server_keys wg_server_pvk wg_server_pbk
  local wg_client_keys wg_client_pvk wg_client_pbk
  echomsg "Generating credentials..." 1
  psk="$(openssl rand -base64 16)" || exiterr "Failed to generate password"
  uuid=$("$PATH_BIN" generate uuid) || exiterr "Failed to generate UUID"
  vless_keys=$("$PATH_BIN" generate reality-keypair) || exiterr "Failed to generate reality keys"
  vless_pvk=$(echo "$vless_keys" | grep 'PrivateKey' | awk '{print $NF}') || exiterr "Failed to extract reality private key"
  vless_pbk=$(echo "$vless_keys" | grep 'PublicKey' | awk '{print $NF}') || exiterr "Failed to extract reality public key"
  vless_sid=$(openssl rand -hex 3) || exiterr "Failed to generate reality short id"
  wg_server_keys=$("$PATH_BIN" generate wg-keypair) || exiterr "Failed to generate wg server keys"
  wg_server_pvk=$(echo "$wg_server_keys" | grep 'PrivateKey' | awk '{print $NF}') || exiterr "Failed to extract wg server private key"
  wg_server_pbk=$(echo "$wg_server_keys" | grep 'PublicKey' | awk '{print $NF}') || exiterr "Failed to extract wg server public key"
  wg_client_keys=$("$PATH_BIN" generate wg-keypair) || exiterr "Failed to generate wg client keys"
  wg_client_pvk=$(echo "$wg_client_keys" | grep 'PrivateKey' | awk '{print $NF}') || exiterr "Failed to extract wg client private key"
  wg_client_pbk=$(echo "$wg_client_keys" | grep 'PublicKey' | awk '{print $NF}') || exiterr "Failed to extract wg client public key"
  set_env_var "PSK" "$psk"
  set_env_var "UUID" "$uuid"
  set_env_var "VLESS_PVK" "$vless_pvk"
  set_env_var "VLESS_PBK" "$vless_pbk"
  set_env_var "VLESS_SID" "$vless_sid"
  set_env_var "WG_SERVER_PVK" "$wg_server_pvk"
  set_env_var "WG_SERVER_PBK" "$wg_server_pbk"
  set_env_var "WG_CLIENT_PVK" "$wg_client_pvk"
  set_env_var "WG_CLIENT_PBK" "$wg_client_pbk"
}

urlencode() { jq -rn --arg x "$1" '$x|@uri'; }

create_base_config(){
cat > "$PATH_CONFIG_DIR/base.json" <<EOF_BASE
{
  "log": {
    "level": "warn",
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

get_ssl_settings(){
  [[ -z "$SSL_TYPE" ]] && return 0
  if [[ "$SSL_TYPE" == "path-ssl" ]]; then
    cat <<SSL_PATH
        "certificate_path": "${SSL_CERTIFICATE_PATH}",
        "key_path": "${SSL_KEY_PATH}"
SSL_PATH
    return
  fi
  local block
  block+=$(cat <<ACME_COMMON
        "acme": {
          "domain": "${ACME_DOMAIN}",
          "default_server_name": "${ACME_DOMAIN}",
          "email": "${ACME_EMAIL}",
          "provider": "${ACME_PROVIDER}",
ACME_COMMON
  )
  case "$SSL_TYPE" in
    zerossl-*)
      block+=$(cat <<EAB_BLOCK
\n          "external_account": {
            "key_id": "${ZEROSSL_EAB_KID}",
            "mac_key": "${ZEROSSL_EAB_HMAC_KEY}"
          },
EAB_BLOCK
      )
    ;;
  esac
  case "$SSL_TYPE" in
    *dns01-cloudflare)
      block+=$(cat <<DNS01_BLOCK
\n          "dns01_challenge": {
            "provider": "${DNS01_PROVIDER}",
            "api_token": "${CLOUDFLARE_API_TOKEN}"
          },
DNS01_BLOCK
      )
    ;;
  esac
  block+="\n          \"data_directory\": \"${PATH_ACME_DIR}\"\n        }"
  echo -e "$block"
}

create_inbound_config(){
  local type="$1"
  case "$type" in
    Shadowsocks2022-TCP-UDP)
      local psk base64_part
      local method="2022-blake3-aes-128-gcm"
cat > "$PATH_INBOUND" <<EOF_SS2022_TCP_UDP
{
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "method": "${method}",
      "password": "${PSK}"
    }
  ]
}
EOF_SS2022_TCP_UDP
    echo "green \"ss://\$(echo -n "${method}:\${PSK}" | base64 -w0)@\${PUBLIC_IP}:\${LISTEN_PORT}/?type=tcp#WGDS\"" \
    > "$PATH_CLIENT_LINK"
    ;;


    Shadowsocks2022-TCP-Multiplex)
      local psk base64_part
      local method="2022-blake3-aes-128-gcm"
cat > "$PATH_INBOUND" <<EOF_SS2022_TCP_MULTIPLEX
{
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "network": "tcp",
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "method": "${method}",
      "password": "${PSK}",
      "multiplex": {
        "enabled": true
      }
    }
  ]
}
EOF_SS2022_TCP_MULTIPLEX
      echo "green \"ss://\$(echo -n "${method}:\${PSK}" | base64 -w0)@\${PUBLIC_IP}:\${LISTEN_PORT}/?type=tcp&multiplex=h2mux#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    VLESS-TCP-XTLS-Vision-REALITY)
cat > "$PATH_INBOUND" <<EOF_VLESS_TCP_REALITY_VISION
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "users": [{
        "uuid": "${UUID}",
        "flow": "xtls-rprx-vision"
      }],
      "tls": {
        "enabled": true,
        "server_name": "${MASK_DOMAIN}",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${MASK_DOMAIN}",
            "server_port": 443
          },
          "private_key": "${VLESS_PVK}",
          "short_id": ["${VLESS_SID}"]
        }
      }
    }
  ]
}
EOF_VLESS_TCP_REALITY_VISION
      echo "green \"vless://\${UUID}@\${PUBLIC_IP}:\${LISTEN_PORT}/?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&pbk=\${VLESS_PBK}&sid=\${VLESS_SID}&sni=\${MASK_DOMAIN}&alpn=h2&fp=chrome#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    VLESS-TCP-XTLS-Vision)
cat > "$PATH_INBOUND" <<EOF_VLESS_TCP_TLS_VISION
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "users": [{
        "uuid": "${UUID}",
        "flow": "xtls-rprx-vision"
      }],
      "tls": {
        "enabled": true,
        "server_name": "${ACME_DOMAIN}",
        "alpn": ["h2"],
$(get_ssl_settings)
      }
    }
  ]
}
EOF_VLESS_TCP_TLS_VISION
      echo "green \"vless://\${UUID}@\${PUBLIC_IP}:\${LISTEN_PORT}/?type=tcp&security=tls&encryption=none&flow=xtls-rprx-vision&sni=\${ACME_DOMAIN}&alpn=h2&fp=chrome#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    VLESS-TCP-TLS-Multiplex)
cat > "$PATH_INBOUND" <<EOF_VLESS_TCP_TLS_MULTIPLEX
{
  "inbounds": [
    {
      "type": "vless",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "tcp_fast_open": true,
      "tcp_multi_path": true,
      "users": [{
        "uuid": "${UUID}"
      }],
      "tls": {
        "enabled": true,
        "server_name": "${ACME_DOMAIN}",
        "alpn": ["h2"],
$(get_ssl_settings)
      },
      "multiplex": {
        "enabled": true
      }
    }
  ]
}
EOF_VLESS_TCP_TLS_MULTIPLEX
      echo "green \"vless://\${UUID}@\${PUBLIC_IP}:\${LISTEN_PORT}/?type=tcp&security=tls&encryption=none&flow=xtls-rprx-vision&sni=\${ACME_DOMAIN}&alpn=h2&fp=chrome&multiplex=h2mux#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    Trojan-TCP-TLS)
cat > "$PATH_INBOUND" <<EOF_TROJAN_TCP_TLS
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "users": [{
        "password": "${PSK}"
      }],
      "tls": {
        "enabled": true,
        "server_name": "${ACME_DOMAIN}",
        "alpn": ["h2"],
$(get_ssl_settings)
      }
    }
  ]
}
EOF_TROJAN_TCP_TLS
      echo "green \"trojan://\$(urlencode "\$PSK")@\${PUBLIC_IP}:\${LISTEN_PORT}/?type=tcp&security=tls&encryption=none&sni=\${ACME_DOMAIN}&alpn=h2&fp=chrome#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    Trojan-TCP-TLS-Multiplex)
cat > "$PATH_INBOUND" <<EOF_TROJAN_TCP_TLS_MULTIPLEX
{
  "inbounds": [
    {
      "type": "trojan",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "users": [{
        "password": "${PSK}>"
      }],
      "tls": {
        "enabled": true,
        "server_name": "${ACME_DOMAIN}",
        "alpn": ["h2"],
$(get_ssl_settings)
      },
      "multiplex": {
        "enabled": true
      }
    }
  ]
}
EOF_TROJAN_TCP_TLS_MULTIPLEX
      echo "green \"trojan://\$(urlencode "\$PSK")@\${PUBLIC_IP}:\${LISTEN_PORT}/?type=tcp&security=tls&encryption=none&sni=\${ACME_DOMAIN}&alpn=h2&fp=chrome&multiplex=h2mux#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    Hysteria2)
cat > "$PATH_INBOUND" <<EOF_HY2
{
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "users": [{
        "password": "${PSK}"
      }],
      "masquerade": "https://${MASK_DOMAIN}",
      "tls": {
         "enabled": true,
         "server_name": "${ACME_DOMAIN}",
         "alpn": ["h3"],
$(get_ssl_settings)
       }
    }
  ]
}
EOF_HY2
      echo "green \"hy2://\$(urlencode "\$PSK")@\${PUBLIC_IP}:\${LISTEN_PORT}/?sni=\${ACME_DOMAIN}&alpn=h3&insecure=0#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    TUIC)
cat > "$PATH_INBOUND" <<TUIC
{
  "inbounds": [
    {
      "type": "tuic",
      "tag": "${type}",
      "listen": "::",
      "listen_port": ${LISTEN_PORT},
      "congestion_control": "bbr",
      "users": [{
        "uuid": "${UUID}",
        "password": "${PSK}"
      }],
      "tls": {
         "enabled": true,
         "server_name": "${ACME_DOMAIN}",
         "alpn": ["h3"],
$(get_ssl_settings)
       }
    }
  ]
}
TUIC
      echo "green \"tuic://\${UUID}:\$(urlencode "\$PSK")@\${PUBLIC_IP}:\${LISTEN_PORT}/?sni=\${ACME_DOMAIN}&alpn=h3&congestion_control=bbr&udp_relay_mode=native#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;


    WireGuard)
cat > "$PATH_INBOUND" <<WIREGUARD
{
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "${type}",
      "system": false,
      "mtu": 1408,
      "address": ["10.0.0.1/24", "fd86:ea04:1115::1/64"],
      "private_key": "${WG_SERVER_PVK}",
      "listen_port": ${LISTEN_PORT},
      "udp_timeout": "5m0s",
      "peers": [
        {
          "public_key": "${WG_CLIENT_PBK}",
          "allowed_ips": ["10.0.0.2/32", "fd86:ea04:1115::2/128"],
          "reserved": [0, 0, 0]
        }
      ]
    }
  ]
}
WIREGUARD
      echo "green \"wg://\${PUBLIC_IP}:\${LISTEN_PORT}?pk=\$(urlencode "\$WG_CLIENT_PVK")&local_address=10.0.0.2/32,fd86:ea04:1115::2/128&peer_public_key=\$(urlencode "\$WG_SERVER_PBK")&mtu=1408#WGDS\"" \
      > "$PATH_CLIENT_LINK"
    ;;

    *)
      exiterr "Inbound '${type}' is not available"
    ;;
  esac
}

apply_inbound_config(){
  local type="$1"
  . "$PATH_ENV_FILE"
  [[ -n "$type" ]] || type="$ACTIVE_INBOUND"
  [[ -f "${PATH_CONFIG_DIR}/base.json" ]] || create_base_config
  create_inbound_config "$type"
  set_env_var "ACTIVE_INBOUND" "$type"
  . "$PATH_ENV_FILE"
}

create_configs(){
  echomsg "Creating sing-box configurations..." 1
  mkdir -p "$PATH_CONFIG_DIR" "$PATH_ACME_DIR"
  apply_inbound_config "Shadowsocks2022-TCP-UDP"
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
    echo "Description=${SINGBOX} server"
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
    echo "ExecStopPost=${iptables_path} -D INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT"
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
  local protocols options next option name
  show_header
  . "$PATH_ENV_FILE"
  if [[ -n "$SSL_TYPE" ]]; then
    protocols=("${INBOUNDS[@]}" "${INBOUNDS_SSL[@]}")
  else
    protocols=("${INBOUNDS[@]}")
  fi
  [[ ${#protocols[@]} -eq 0 ]] && exiterr "No protocols available"
  echomsg "Select the protocol to be used by default:"
  options=""
  for i in "${!protocols[@]}"; do
    name="${protocols[i]}"
    if [[ "$ACTIVE_INBOUND" == "$name" ]]; then
      options+=" $(green "$((i+1)). ${name}")\n"
    else
      options+=" $(green "$((i+1)).") ${name}\n"
    fi
  done
  next=$((${#protocols[@]} + 1))
  options+=" $(green "${next}.") 📖 Back menu"
  echo -e "$options"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[0-9]+$ ]] && (( 10#$option >= 1 && 10#$option <= next )); do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
  if [[ "$option" == "$next" ]]; then
    select_menu_option
    return 0
  fi
  name="${protocols[option-1]}"
  if [[ "$ACTIVE_INBOUND" != "$name" ]]; then
    echomsg "Setting the active protocol..." 1
    apply_inbound_config "$name"
    if systemctl is-active --quiet "${SINGBOX}"; then
      systemctl restart ${SINGBOX} >/dev/null 2>&1
      wait_start_singbox
    fi
  else
    echo
  fi
  echook "The active protocol is set to '$name'"
  press_any_side_to_open_menu
}

change_listen_port(){
  local listen_port
  show_header
  echo -e "$(cyan "Current port:") $(green "${LISTEN_PORT}")\n"
  while true; do
    echomsg "Enter the new port number for the VPN service:"
    read -e -i "$LISTEN_PORT" -rp " > " listen_port
    if check_port "$listen_port"; then
      break
    fi
  done
  if [[ "$LISTEN_PORT" == "$listen_port" ]]; then
    select_menu_option
    return 0
  fi
  echomsg "Setting the new port..." 1
  set_env_var "LISTEN_PORT" "$listen_port"
  apply_inbound_config
  if systemctl is-active --quiet "${SINGBOX}"; then
    systemctl restart ${SINGBOX} >/dev/null 2>&1
    wait_start_singbox
  fi
  echook "The new port is set to ${listen_port}"
  press_any_side_to_open_menu
}

change_ssl_settings(){
  input_acme_provider
  apply_inbound_config
  if [[ "$is_acme_completed" -eq 1 ]]; then
    if systemctl is-active --quiet "${SINGBOX}"; then
      systemctl restart ${SINGBOX} >/dev/null 2>&1
      wait_start_singbox
    fi
    echook "SSL configuration completed"
    read -n1 -r -p "Press any key to back menu..."
  fi
  show_ssl_settings
}

change_masking_domain(){
  input_masking_domain
  if systemctl is-active --quiet "${SINGBOX}"; then
    systemctl restart ${SINGBOX} >/dev/null 2>&1
    wait_start_singbox
  fi
  echook "Mask domain has been changed"
  read -n1 -r -p "Press any key to back menu..."
  show_ssl_settings
}

show_ssl_settings(){
  local menu=""
  show_header
  . "$PATH_ENV_FILE"
  if [[ -n "$SSL_TYPE" ]]; then
    menu+="$(cyan "Domain:") $(green "${ACME_DOMAIN}")\n"
    if [[ "$SSL_TYPE" != "path-ssl" ]]; then
      menu+="$(cyan "Email:") $(green "${ACME_EMAIL}")\n"
      menu+="$(cyan "Provider:") $(green "${ACME_PROVIDER}")\n"
      menu+="$(cyan "Challenge type:") $(green "${SSL_TYPE#*-}")\n"
      menu+="$(cyan "ACME directory:") $(green "${PATH_ACME_DIR}")\n"
    else
      menu+="$(cyan "Certificate path:") $(green "${SSL_CERTIFICATE_PATH}")\n"
      menu+="$(cyan "Key path:") $(green "${SSL_KEY_PATH}")\n"
    fi
  else
    menu+="$(red "SSL not configured")\n"
  fi
  menu+="-----------------------------------------------\n"
  menu+="$(cyan "Mask domain:") $(green "${MASK_DOMAIN}")\n"
  menu+="\n$(cyan "Select option:")\n"
  menu+=" $(green "1.") 🌍 Change SSL settings\n"
  menu+=" $(green "2.") 🎭 Change the masking domain\n"
  menu+=" $(green "3.") 📖 Back menu"
  echo -e "$menu"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-3]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
  case "$option" in
    1) change_ssl_settings;;
    2) change_masking_domain;;
    3) select_menu_option;;
  esac
}

wait_start_singbox(){
  local timeout=10
  while ! systemctl is-active --quiet "${SINGBOX}" && [ $timeout -gt 0 ]; do
    sleep 1
    ((timeout--))
  done
  if systemctl is-active --quiet "${SINGBOX}"; then
    return 0
  fi
  return 1
}

start_service(){
  local timeout=10
  systemctl daemon-reload >/dev/null 2>&1
  echomsg "Starting service..." 1
  systemctl enable "${SINGBOX}" >/dev/null 2>&1
  systemctl start "${SINGBOX}" >/dev/null 2>&1
  if wait_start_singbox; then
    echook "Service launched successfully"
  else
    echoerr "Failed to launch the service"
  fi
}

wait_stop_singbox(){
  local timeout=10
  while systemctl is-active --quiet "${SINGBOX}" && [ $timeout -gt 0 ]; do
    sleep 1
    ((timeout--))
  done
  if ! systemctl is-active --quiet "${SINGBOX}"; then
    return 0
  fi
  return 1
}

stop_service(){
  echomsg "Stopping service..." 1
  systemctl stop "${SINGBOX}" >/dev/null 2>&1
  systemctl disable "${SINGBOX}" >/dev/null 2>&1
  if wait_stop_singbox; then
    echook "Service stopped successfully"
  else
    echoerr "Failed to stop the service"
  fi
}

press_any_side_to_open_menu(){
  echomsg "------------------------------------------------"
  read -n1 -r -p "Press any key to open menu..."
  select_menu_option
}

restart_service() {
  echomsg "Restarting service..." 1
  systemctl daemon-reload >/dev/null 2>&1
  systemctl restart "${SINGBOX}" >/dev/null 2>&1
  if wait_start_singbox; then
    echook "Service ${SINGBOX} is successfully restarted"
  else
    echoerr "Failed to restart service ${SINGBOX}"
  fi
  press_any_side_to_open_menu
}

switch_active_service(){
  if systemctl is-active --quiet "${SINGBOX}"; then
    stop_service
  else
    start_service
  fi
  press_any_side_to_open_menu
}

echo_connect_link(){
  [[ -f "$PATH_CLIENT_LINK" ]] || exiterr "Link file not found"
  . "$PATH_CLIENT_LINK"
}

recreate_link(){
  echomsg "Recreating connection link..."
  generate_credentials
  . "$PATH_ENV_FILE"
  if systemctl is-active --quiet "${SINGBOX}"; then
    echomsg "Restarting service..."
    systemctl restart "${SINGBOX}" >/dev/null 2>&1
    wait_start_singbox
  fi
  echook "The connection link has been recreated"
  read -n1 -r -p "Press any key to view the new link..."
  show_connect_link
}

show_connect_link(){
  show_header
  cyan "Client link:"
  echo_connect_link
  echo -e "\n$(cyan "Select option:")"
  echo -e " $(green "1.") 🔑 Recreate\n $(green "2.") 📖 Back menu"
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
    stop_service
    rm -rf "$PATH_CONFIG_DIR"
    rm -f "$PATH_ENV_FILE"
    rm -f "$PATH_SERVICE"
    rm -rf "$PATH_CONFIG_DIR"
    rm -f "$PATH_INBOUND"
    rm -f "$PATH_CLIENT_LINK"
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
  show_header
  read -rp "Uninstall application? [y/n]: " remove
  until [[ "$remove" =~ ^[yYnN]*$ ]]; do
    echo "Incorrect option"
    read -rp "Uninstall application? [y/n]: " remove
  done
  if [[ "$remove" =~ ^[yY]$ ]]; then
    echomsg "Uninstalling a program..." 1
    uninstall
    if [[ -d "${PATH_ACME_DIR}/certificates" ]]; then
      read -rp "Uninstall certificates? [y/n]: " remove_certs
      until [[ "$remove" =~ ^[yYnN]*$ ]]; do
        echo "Incorrect option"
        read -rp "Uninstall certificates? [y/n]: " remove_certs
      done
      echomsg "Uninstalling certificates..." 1
      [[ "$remove_certs" =~ ^[yY]$ ]] && rm -rf "$PATH_ACME_DIR" >/dev/null 2>&1
    fi
    echook "Files and services deleted"
    exit 0
  else
    select_menu_option
  fi
}

install(){
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
  input_acme_provider
  input_listen_port
  set_public_ip
  download_singbox
  create_sysctl_config
  generate_credentials
  create_configs
  create_service
  add_user
  start_service

  mkdir -p "$(dirname "$PATH_SCRIPT")"
  curl -fsSL -o "$PATH_SCRIPT" \
    "https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/scripts/sing-box-server-install.sh" \
    || exiterr "Failed to download the management script"
  chmod +x "$PATH_SCRIPT"
  ln -s "$PATH_SCRIPT" "$PATH_SCRIPT_LINK"
  echook "Installation is completed"
  press_any_side_to_open_menu
}

select_menu_option(){
  local menu
  show_header
  menu+="$(cyan "Protocol:") $(green "${ACTIVE_INBOUND}")\n"
  menu+="$(cyan "Listen port:") $(green "${LISTEN_PORT}")\n"

  if systemctl is-active --quiet "${SINGBOX}"; then
    menu+="$(cyan "Service status:") $(green "active")\n"
    menu+="\n$(cyan "Select option:")\n"
    menu+=" $(green "1.") ❌ Stop service\n"
  else
    menu+="$(cyan "Service status:") $(red "not active")\n"
    menu+="\n$(cyan "Select option:")\n"
    menu+=" $(green "1.") 🚀 Start service\n"
  fi
  menu+=" $(green "2.") 🌀 Restart service\n"
  menu+=" $(green "3.") 🧿 Status service\n"
  menu+=" $(green "4.") 🔗 Connection link\n"
  menu+=" $(green "5.") ✨ Change protocol\n"
  menu+=" $(green "6.") 🔌 Change port\n"
  menu+=" $(green "7.") 🌐 SSL settings\n"
  menu+=" $(green "8.") 📜 Last logs\n"
  menu+=" $(green "9.") 🪣 Uninstall\n"
  menu+=" $(green "Ctrl+C.") 🚪 Exit"
  echo -e "$menu"
  read -rp "Choice: " option
  until [[ "$option" =~ ^[1-9]$ ]]; do
    echoerr "Incorrect option"
    read -rp "Choice: " option
  done
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

run(){
  if [[ -n "$NEW_VERSION" && "$NEW_VERSION" != "$CUR_VERSION" ]]; then
    echo -e "$(cyan "A new version of the sing-box core is available:") $(green "$NEW_VERSION")"
    echo -e "$(cyan "Current version:") $(red "$CUR_VERSION")"
    echo -e "$(cyan "More details:") $(green "https://github.com/SagerNet/sing-box/releases")"
    read -rp "Perform the update? [y/n]: " option
    until [[ "$option" =~ ^[yYnN]*$ ]]; do
      echo "Incorrect option"
      read -rp "Perform the update? [y/n]: " option
    done
    if [[ "$option" =~ ^[yY]$ ]]; then
      local is_stopped=0
      if systemctl is-active --quiet "${SINGBOX}"; then
        stop_service
        is_stopped=1
      fi
      rm -rf "$PATH_BIN_DIR"
      download_singbox "$NEW_VERSION"
      if [[ "$is_stopped" -eq 1 ]]; then
        start_service
      fi
      echook "The sing-box core has been successfully updated"
      press_any_side_to_open_menu
    fi
  fi
  if [[ -f "$PATH_SCRIPT" ]]; then
    select_menu_option
  else
    install
  fi
}

run
