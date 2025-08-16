#!/bin/bash

# Path to the configuration file (exists because of previous function).
wgd_config_file="/data/wg-dashboard.ini"

trap 'stop_service' SIGTERM

log(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

stop_service() {
  log "[WGDashboard] Stopping WGDashboard..."
  /bin/bash ./wgd.sh stop
  exit 0
}

echo -e "\n------------------------- START ----------------------------"
log "Starting the WireGuard Dashboard Docker container."

ensure_installation() {
  # When using a custom directory to store the files, this part moves over and makes sure the installation continues.
  log "Quick-installing..."

  # Make the wgd.sh script executable.
  # WGDASH=/opt/wgdashboard
  chmod +x "${WGDASH}"/src/wgd.sh
  cd "${WGDASH}"/src || exit

  # Github issue: https://github.com/donaldzou/WGDashboard/issues/723
  log "Checking for stale pids..."
  if [[ -f "${WGDASH}/src/gunicorn.pid" ]]; then
    log "Found stale pid, removing..."
    rm "${WGDASH}/src/gunicorn.pid"
  fi

  # Removing clear shell command from the wgd.sh script to enhance docker logging.
  log "Removing clear command from wgd.sh for better Docker logging."
  sed -i '/clear/d' ./wgd.sh

  # Create the databases directory if it does not exist yet.
  if [ ! -d "/data/db" ]; then
    log "Creating database dir"
    mkdir -p /data/db
  fi

  # Linking the database on the persistent directory location to where WGDashboard expects.
  if [ ! -d "${WGDASH}/src/db" ]; then
    log "Linking database dir"
    ln -s /data/db "${WGDASH}/src/db"
  fi

  # Create the wg-dashboard.ini file if it does not exist yet.
  if [ ! -f "${wgd_config_file}" ]; then
    log "Creating wg-dashboard.ini file"
    touch "${wgd_config_file}"
  fi

  # Link the wg-dashboard.ini file from the persistent directory to where WGDashboard expects it.
  if [ ! -f "${WGDASH}/src/wg-dashboard.ini" ]; then
    log "Link the wg-dashboard.ini file"
    ln -s "${wgd_config_file}" "${WGDASH}/src/wg-dashboard.ini"
  fi

  # Create the Python virtual environment.
  python3 -m venv "${WGDASH}"/src/venv
  # shellcheck source=/dev/null
  source "${WGDASH}/src/venv/bin/activate"

  # Due to this pip dependency being available as a system package we can just move it to the venv.
  log "Moving PIP dependency from ephemerality to runtime environment: psutil"
  mv /usr/lib/python3.12/site-packages/psutil* "${WGDASH}"/src/venv/lib/python3.12/site-packages

  # Due to this pip dependency being available as a system package we can just move it to the venv.
  log "Moving PIP dependency from ephemerality to runtime environment: bcrypt"
  mv /usr/lib/python3.12/site-packages/bcrypt* "${WGDASH}"/src/venv/lib/python3.12/site-packages

  # Use the bash interpreter to install WGDashboard according to the wgd.sh script.
  /bin/bash ./wgd.sh install

  log "Looks like the installation succeeded. Moving on."

  # This first step is to ensure the wg0.conf file exists, and if not, then its copied over from the ephemeral container storage.
  # This is done so WGDashboard it works out of the box, it also sets a randomly generated private key.

  if [ ! -f "/etc/wireguard/wg0.conf" ]; then
    log "Standard wg0 Configuration file not found, grabbing template."
    cp -a "/configs/wg0.conf.template" "/etc/wireguard/wg0.conf"

    log "Setting a secure private key."

    local privateKey
    privateKey=$(wg genkey)
    sed -i "s|^PrivateKey *=.*$|PrivateKey = ${privateKey}|g" /etc/wireguard/wg0.conf

    log "Done setting template."
  else
    log "Existing wg0 configuration file found, using that."
  fi
}

set_envvars() {
  echo -e "\n------------- SETTING ENVIRONMENT VARIABLES ----------------"

  local current_dns current_public_ip default_ip current_wgd_port current_app_prefix
  local app_prefix="${WGD_PATH-}"
  local public_ip="${WGD_HOST:-}"
  local wgd_port="${WGD_PORT:-10086}"
  local global_dns="${DNS_CLIENTS:-1.1.1.1}"

  # Check if the file is empty
  if [ ! -s "${wgd_config_file}" ]; then
    log "Config file is empty. Creating [Peers] section."

    # Create [Peers] section with initial values
    {
      echo "[Peers]"
      echo "peer_global_dns = ${global_dns}"
      echo "remote_endpoint = ${public_ip}"
      echo -e "\n[Server]"
      echo "app_port = ${wgd_port}"
      echo "app_prefix = /${app_prefix}"
    } > "${wgd_config_file}"

  else
    log "Config file is not empty, using pre-existing."
  fi

  log "Verifying current variables..."

  # Check and update the DNS if it has changed
  current_dns=$(grep "peer_global_dns = " "${wgd_config_file}" | awk '{print $NF}')
  if [ "${global_dns}" == "$current_dns" ]; then
    log "DNS is set correctly, moving on."
  else
    log "Changing default DNS..."
    sed -i "s/^peer_global_dns = .*/peer_global_dns = ${global_dns}/" "${wgd_config_file}"
  fi

  # Checking the current set public IP and changing it if it has changed.
  current_public_ip=$(grep "remote_endpoint = " "${wgd_config_file}" | awk '{print $NF}')
  if [ "${public_ip}" == "" ]; then
    default_ip=$(curl -s ifconfig.me)
    [ -z "$default_ip" ] && public_ip=$(curl -s https://api.ipify.org)
    [ -z "$default_ip" ] && log "Not set 'WGD_HOST' var" && exit 1

    log "Trying to fetch the Public-IP using curl: ${default_ip}"
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${default_ip}/" "${wgd_config_file}"
  elif [ "${current_public_ip}" != "${public_ip}" ]; then
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${public_ip}/" "${wgd_config_file}"
  else
    log "Public-IP is correct, moving on."
  fi

  # Checking the current WGDashboard web port and changing if needed.
  current_wgd_port=$(grep "app_port = " "${wgd_config_file}" | awk '{print $NF}')
  if [ "${current_wgd_port}" == "${wgd_port}" ]; then
    log "Current WGD port is set correctly, moving on."
  else
    log "Changing default WGD port..."
    sed -i "s/^app_port = .*/app_port = ${wgd_port}/" "${wgd_config_file}"
  fi

  # Checking the current WGDashboard app prefix and changing if needed.
  current_app_prefix=$(grep "app_prefix =" "${wgd_config_file}" | awk '{print $NF}')
  if [ "/${current_app_prefix}" == "/${app_prefix}" ]; then
    log "Current WGD app_prefix is set correctly, moving on."
  else
    log "Changing default WGD UI_BASE_PATH..."
    sed -i "s|^app_prefix = .*|app_prefix = /${app_prefix}|" "${wgd_config_file}"
  fi
}

network_optimization(){
  echo -e "\n------------------ NETWORK OPTIMIZATION --------------------"

  if modprobe -q tcp_bbr; then
    {
      echo "net.core.default_qdisc = fq"
      echo "net.ipv4.tcp_congestion_control = bbr"
    } >> /etc/sysctl.conf
    log "Module tcp_bbr loaded"
  elif modprobe -q tcp_hybla; then
    echo "net.ipv4.tcp_congestion_control = hybla" >> /etc/sysctl.conf
    log "Module tcp_hybla loaded"
  fi

  /sbin/sysctl -p >/dev/null 2>&1 
  log "Sysctl configuration applied"
}

start_sing_box() {
  echo -e "\n-------------------- STARTING SING-BOX ---------------------"
  log "sing-box creating config"

  local path_singbox_config="/data/singbox.json"
  local path_singbox_log="/data/singbox.log"
  local path_singbox_cache="/data/singbox.db"
  local singbox_tun_name="singbox"

  dns_direct="${DNS_DIRECT:-77.88.8.8}"
  dns_proxy="${DNS_PROXY:-1.1.1.1}"
  
  proxy_link="${PROXY_LINK:-}"
  cidr_proxy="${CIDR_PROXY:-10.10.10.0/24}"
  geosite_bypass="${GEOSITE_BYPASS:-}"
  geoip_bypass="${GEOIP_BYPASS:-}"
  geo_no_domains="${GEO_NO_DOMAINS:-}"

  gen_proxy_inbound(){
    [ -n "$proxy_link" ] && \
    /bin/bash /vless-parse.sh "$proxy_link" && \
    echo ",{\"tag\":\"proxy\",\"type\":\"vless\",\"server\":\"${VLESS_HOST}\",\"server_port\":${VLESS_PORT},
    \"uuid\":\"${VLESS_UUID}\",\"flow\":\"xtls-rprx-vision\",\"packet_encoding\":\"xudp\",\"domain_resolver\":\"dns-proxy\",
    \"tls\":{\"enabled\":true,\"insecure\":false,\"server_name\":\"${VLESS_SNI}\",
    \"utls\":{\"enabled\":true,\"fingerprint\":\"${VLESS_FP}\"},
    \"reality\":{\"enabled\":true,\"public_key\":\"${VLESS_PBK}\",\"short_id\":\"${VLESS_SID}\"}}}"
  }

  gen_rule_sets() {
    local rules="$1"
    local first_rule=true

    IFS=',' read -ra entries <<< "$rules"
    for rule in "${entries[@]}"; do
      [ "$first_rule" = true ] && first_rule=false || echo ","
      local base_url="https://raw.githubusercontent.com/SagerNet/sing-${rule%%-*}/rule-set/${rule}.srs"
      echo "{\"tag\":\"${rule}\",\"type\":\"remote\",\"format\":\"binary\",\"url\":\"${base_url}\",
        \"download_detour\":\"proxy\",\"update_interval\":\"1d\"}"
    done
  }

cat << EOF > "$path_singbox_config"
{
  "log": {"level": "warn", "timestamp": true},
  "dns": {
    "servers": [
      {"tag": "dns-direct", "type": "https", "server": "${dns_direct}", "detour": "direct"},
      {"tag": "dns-proxy", "type": "https", "server": "${dns_proxy}", "detour": "proxy"}
    ],
    "rules": [     
      {"rule_set": "geosite-category-ads-all", "action": "reject"}
    ],
    "final": "dns-direct",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "tag": "tun-in", "type": "tun", "interface_name": "${singbox_tun_name}", "address": "172.18.0.1/30",
      "mtu": 1500, "auto_route": true, "auto_redirect": true, "strict_route": true, "stack": "system"
    }
  ],
  "outbounds": [
    {"tag": "direct", "type": "direct", "domain_resolver": "dns-direct"}
    $(gen_proxy_inbound)
  ],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "direct"}
    ],
    "rule_set": [
      $(gen_rule_sets "geosite-category-ads-all")
    ],
    "final": "direct",
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-direct"
  },
  "experimental": {
    "cache_file": {"enabled": true, "path": "${path_singbox_cache}"}
  }
}
EOF

  mergeconf() {
    local patch_file="$1"
    local tmpout
    tmpout=$(mktemp 2>/dev/null)

    if ! sing-box merge "$tmpout" \
      -c "$path_singbox_config" -c "$patch_file" \
      >/dev/null 2>&1; 
    then
      log "sing-box merge config error"
      rm -f "$patch_file" "$tmpout"
      exit 1
    fi

    mv "$tmpout" "$path_singbox_config"
    rm -f "$patch_file"
  }

  add_all_rule_sets() {
    local tmpfile

    log "sing-box add route rules"

    [ -n "$cidr_proxy" ] && cidr_proxy_format="\"${cidr_proxy//,/\",\"}\""

    if [ -z "$geosite_bypass" ] && [ -z "$geoip_bypass" ] 
    then
      [ -n "$cidr_proxy" ] && tmpfile=$(mktemp 2>/dev/null) && \
      {
        echo "{\"dns\":{\"rules\":[{\"source_ip_cidr\":[${cidr_proxy_format}],\"server\":\"dns-proxy\"}]},"
        echo "\"route\":{\"rules\":[{\"source_ip_cidr\":[${cidr_proxy_format}],\"outbound\":\"proxy\"}]}}"
      } > "$tmpfile" && mergeconf "$tmpfile"
      return
    fi

    tmpfile=$(mktemp 2>/dev/null)

    local geo_bypass_list geo_bypass_format

    [ -n "$geo_no_domains" ] && geo_no_domains="\"${geo_no_domains//,/\",\"}\"" 
    [ -n "$geosite_bypass" ] && geo_bypass_list="geosite-${geosite_bypass//,/\,geosite-}"
    [ -n "$geosite_bypass" ] && [ -n "$geoip_bypass" ] && geo_bypass_list+=","
    [ -n "$geoip_bypass" ] && geo_bypass_list+="geoip-${geoip_bypass//,/\,geoip-}"
    geo_bypass_format="\"${geo_bypass_list//,/\",\"}\""

    {
      echo "{\"dns\":{\"rules\":[{\"rule_set\":[${geo_bypass_format}],\"server\":\"dns-direct\"}"
      [ -z "$cidr_proxy" ] && echo "]}," || echo ",{\"source_ip_cidr\":[${cidr_proxy_format}],\"server\":\"dns-proxy\"}]},"
      echo '"route":{"rules":['
      [ -n "$geo_no_domains" ] && echo "{\"domain_keyword\":[${geo_no_domains}],\"outbound\":\"proxy\"},"
      echo "{\"rule_set\":[${geo_bypass_format}],\"outbound\":\"direct\"}"
      [ -z "$cidr_proxy" ] && echo "]," || echo ",{\"source_ip_cidr\":[${cidr_proxy_format}],\"outbound\":\"proxy\"}],"
      echo "\"rule_set\":[$(gen_rule_sets "$geo_bypass_list")]}}"
    } > "$tmpfile"

    mergeconf "$tmpfile"
  }

  add_all_rule_sets

  log "sing-box check config"
  sing-box check -c "$path_singbox_config" >/dev/null 2>&1 || {
    log "sing-box config syntax error" && exit 1
  }

  log "sing-box format config"
  sing-box format -w -c "$path_singbox_config" >/dev/null 2>&1 || {
    log "sing-box config formatting error" && exit 1
  }

  log "Launch sing-box"
  nohup sing-box run -c "$path_singbox_config" \
    --disable-color > "$path_singbox_log" 2>&1 &
}

start_core() {
  echo -e "\n---------------------- STARTING CORE -----------------------"

  # Create the necessary file structure for /dev/net/tun
  if [ ! -c /dev/net/tun ]; then
    if [ ! -d /dev/net ]; then
      mkdir -m 755 /dev/net
    fi
    mknod /dev/net/tun c 10 200
    chmod 0755 /dev/net/tun
  fi

  # Load the tun module if not already loaded
  if ( ! (lsmod | grep -q "^tun\s")); then
    insmod /lib/modules/tun.ko
  fi

  # Actually starting WGDashboard
  log "Activating Python venv and executing the WireGuard Dashboard service."
  /bin/bash ./wgd.sh start
}

ensure_blocking() {
  # Wait a second before continuing, to give the python program some time to get ready.
  sleep 1s
  log "Ensuring container continuation."
  local logdir latestErrLog

  # Find and tail the latest error and access logs if they exist
  logdir="${WGDASH}/src/log"

  latestErrLog=$(find "$logdir" -name "error_*.log" -type f -print | sort -r | head -n 1)

  # Only tail the logs if they are found
  if [ -n "$latestErrLog" ]; then
    tail -f "$latestErrLog" &

    # Wait for the tail process to end.
    wait $!
  else
    log "No log files found to tail. Something went wrong, exiting..."
    exit 1
  fi
}

# Execute functions
ensure_installation
set_envvars
network_optimization
start_sing_box
start_core
ensure_blocking