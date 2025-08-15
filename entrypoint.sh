#!/bin/bash

# Path to the configuration file (exists because of previous function).
config_file="/data/wg-dashboard.ini"

trap 'stop_service' SIGTERM

log(){
  echo "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

stop_service() {
  log "[WGDashboard] Stopping WGDashboard..."
  /bin/bash ./wgd.sh stop
  exit 0
}

log "------------------------- START ----------------------------"
log "Starting the WireGuard Dashboard Docker container."

ensure_installation() {
  # When using a custom directory to store the files, this part moves over and makes sure the installation continues.
  log "Quick-installing..."

  # Make the wgd.sh script executable.
  chmod +x "${WGDASH}"/src/wgd.sh
  cd "${WGDASH}"/src || exit

  # Github issue: https://github.com/donaldzou/WGDashboard/issues/723
  log "Checking for stale pids..."
  if [[ -f ${WGDASH}/src/gunicorn.pid ]]; then
    log "Found stale pid, removing..."
    rm ${WGDASH}/src/gunicorn.pid
  fi

  # Removing clear shell command from the wgd.sh script to enhance docker logging.
  log "Removing clear command from wgd.sh for better Docker logging."
  sed -i '/clear/d' ./wgd.sh

  # Create the databases directory if it does not exist yet.
  if [ ! -d "/data/db" ]; then
    log "Creating database dir"
    mkdir /data/db
  fi

  # Linking the database on the persistent directory location to where WGDashboard expects.
  if [ ! -d "${WGDASH}/src/db" ]; then
    ln -s /data/db "${WGDASH}/src/db"
  fi

  # Create the wg-dashboard.ini file if it does not exist yet.
  if [ ! -f "${config_file}" ]; then
    log "Creating wg-dashboard.ini file"
    touch "${config_file}"
  fi

  # Link the wg-dashboard.ini file from the persistent directory to where WGDashboard expects it.
  if [ ! -f "${WGDASH}/src/wg-dashboard.ini" ]; then
    ln -s "${config_file}" "${WGDASH}/src/wg-dashboard.ini"
  fi

  # Create the Python virtual environment.
  python3 -m venv "${WGDASH}"/src/venv
  . "${WGDASH}/src/venv/bin/activate"

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
  log "------------- SETTING ENVIRONMENT VARIABLES ----------------"

  # Check if the file is empty
  if [ ! -s "${config_file}" ]; then
    log "Config file is empty. Creating [Peers] section."

    # Create [Peers] section with initial values
    {
      echo "[Peers]"
      echo "peer_global_dns = ${global_dns}"
      echo "remote_endpoint = ${public_ip}"
      echo -e "\n[Server]"
      echo "app_port = ${wgd_port}"
    } > "${config_file}"

  else
    log "Config file is not empty, using pre-existing."
  fi

  log "Verifying current variables..."

  # Check and update the DNS if it has changed
  current_dns=$(grep "peer_global_dns = " "${config_file}" | awk '{print $NF}')
  if [ "${global_dns}" == "$current_dns" ]; then
    log "DNS is set correctly, moving on."

  else
    log "Changing default DNS..."
    sed -i "s/^peer_global_dns = .*/peer_global_dns = ${global_dns}/" "${config_file}"
  fi

  # Checking the current set public IP and changing it if it has changed.
  current_public_ip=$(grep "remote_endpoint = " "${config_file}" | awk '{print $NF}')
  if [ "${public_ip}" == "" ]; then
    default_ip=$(curl -s ifconfig.me)

    log "Trying to fetch the Public-IP using ifconfig.me: ${default_ip}"
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${default_ip}/" "${config_file}"
  elif [ "${current_public_ip}" != "${public_ip}" ]; then
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${public_ip}/" "${config_file}"
  else
    log "Public-IP is correct, moving on."
  fi

  # Checking the current WGDashboard web port and changing if needed.
  current_wgd_port=$(grep "app_port = " "${config_file}" | awk '{print $NF}')
  if [ "${current_wgd_port}" == "${wgd_port}" ]; then
    log "Current WGD port is set correctly, moving on."
  else
    log "Changing default WGD port..."
    sed -i "s/^app_port = .*/app_port = ${wgd_port}/" "${config_file}"
  fi
}

start_sing_box() {
  log "---------------------- STARTING SING-BOX -----------------------"

  PATH_SINGBOX_CONFIG="/data/singbox.json"
  PATH_SINGBOX_LOG="/data/singbox.log"
  PATH_SINGBOX_CACHE="/data/singbox.db"
  PATH_EXCLUDE_DOMAINS_BYPASS="/data/exclude_bypass.domains"

  TUN_NAME="singbox"

  LOG_LEVEL="${LOG_LEVEL:-warn}"

  DNS_DIRECT="${DNS_DIRECT:-77.88.8.8}"
  DNS_PROXY="${DNS_PROXY:-1.1.1.1}"

  CIDR_PROXY="${CIDR_PROXY:-10.10.10.0/24}"

  ## Rules for bypassing proxies
  # GEOSITE https://github.com/SagerNet/sing-geosite/tree/rule-set
  # Example: category-ru,geolocation-cn,speedtest
  GEOSITE_BYPASS="${GEOSITE_BYPASS:-}"
  # GEOIP https://github.com/SagerNet/sing-geoip/tree/rule-set
  # Example: ru,by,cn,ir
  GEOIP_BYPASS="${GEOIP_BYPASS:-}"

  ## VLESS Reality
  VLESS_IP="${VLESS_IP:-}"
  VLESS_PORT="${VLESS_PORT:-443}"
  VLESS_ID="${VLESS_ID:-}"
  VLESS_FLOW="${VLESS_FLOW:-xtls-rprx-vision}"
  VLESS_SNI="${VLESS_SNI:-}"
  VLESS_FINGERPRINT="${VLESS_FINGER_PRINT:-chrome}"
  VLESS_PUBLIC_KEY="${VLESS_PUBLIC_KEY:-}"
  VLESS_SHORT_ID="${VLESS_SHORT_ID:-}"

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

cat << EOF > "$PATH_SINGBOX_CONFIG"
{
  "log": {
    "level": "${LOG_LEVEL}",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-direct",
        "type": "tls",
        "server": "${DNS_DIRECT}",
        "detour": "direct"
      },
      {
        "tag": "dns-proxy",
        "type": "tls",
        "server": "${DNS_PROXY}",
        "detour": "proxy"
      }
    ],
    "rules": [     
      {
        "rule_set": "geosite-category-ads-all",
        "action": "reject"
      }
    ],
    "final": "dns-direct",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "tag": "tun-in",
      "type": "tun",
      "interface_name": "$TUN_NAME",
      "mtu": 1500,
      "address": "172.18.0.1/30",
      "auto_route": true,
      "auto_redirect": true,
      "strict_route": true,
      "stack": "system"
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "type": "direct",
      "domain_resolver": "dns-direct",
    },
    {
      "tag": "proxy",
      "type": "vless",
      "server": "${VLESS_IP}",
      "server_port": ${VLESS_PORT},
      "uuid": "${VLESS_ID}",
      "flow": "${VLESS_FLOW}",
      "packet_encoding": "xudp",
      "domain_resolver": "dns-proxy",
      "tls": {
        "enabled": true,
        "insecure": false,
        "server_name": "${VLESS_SNI}",
        "utls": {
          "enabled": true,
          "fingerprint": "${VLESS_FINGERPRINT}"
        },
        "reality": {
          "enabled": true,
          "public_key": "${VLESS_PUBLIC_KEY}",
          "short_id": "${VLESS_SHORT_ID}"
        }
      }
    }
  ],
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      }
    ],
    "rule_set": [
      $(gen_rule_sets "geosite-category-ads-all")
    ],
    "final": "direct",
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-direct"
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "${PATH_SINGBOX_CACHE}"
    }
  }
}
EOF

  mergeconf() {
    local patch_file="$1"
    local tmpout
    tmpout=$(mktemp 2>/dev/null)

    if ! sing-box merge "$tmpout" \
      -c "$PATH_SINGBOX_CONFIG" -c "$patch_file" \
      >/dev/null 2>&1; 
    then
      log "sing-box merge config error"
      rm -f "$patch_file" "$tmpout"
      exit 1
    fi

    mv "$tmpout" "$PATH_SINGBOX_CONFIG"
    rm -f "$patch_file"
  }

  add_all_rule_sets() {
    local tmpfile

    log "sing-box add route rules"

    [ -n "$CIDR_PROXY" ] && CIDR_PROXY_FORMAT="\"${CIDR_PROXY//,/\",\"}\""

    if [ -z "$GEOSITE_BYPASS" ] && [ -z "$GEOIP_BYPASS" ]; then
      [ -n "$CIDR_PROXY" ] && tmpfile=$(mktemp 2>/dev/null) \
        echo "{\"route\":{\"rules\":[{\"source_ip_cidr\":[${CIDR_PROXY_FORMAT}],\"outbound\":\"proxy\"}]}}" \
        > "$tmpfile" && mergeconf "$tmpfile"
      return
    fi

    tmpfile=$(mktemp 2>/dev/null)

    local EXCLUDE_DOMAINS_BYPASS GEO_BYPASS_LIST GEO_BYPASS_FORMAT

    [ -f "$PATH_EXCLUDE_DOMAINS_BYPASS" ] && \
    EXCLUDE_DOMAINS_BYPASS=$(grep -v '^[[:space:]]*$' "$PATH_EXCLUDE_DOMAINS_BYPASS" | paste -sd,) && \
    [ -n "$EXCLUDE_DOMAINS_BYPASS" ] && EXCLUDE_DOMAINS_BYPASS="\"${EXCLUDE_DOMAINS_BYPASS//,/\",\"}\"" 

    [ -n "$GEOSITE_BYPASS" ] && GEO_BYPASS_LIST="geosite-${GEOSITE_BYPASS//,/\,geosite-}"
    [ -n "$GEOSITE_BYPASS" ] && [ -n "$GEOIP_BYPASS" ] && GEO_BYPASS_LIST+=","
    [ -n "$GEOIP_BYPASS" ] && GEO_BYPASS_LIST+="geoip-${GEOIP_BYPASS//,/\,geoip-}"
    GEO_BYPASS_FORMAT="\"${GEO_BYPASS_LIST//,/\",\"}\""

    {
      echo "{\"dns\":{\"rules\":[{\"rule_set\":[${GEO_BYPASS_FORMAT}],\"server\":\"dns-direct\"}]},"
      echo '"route":{"rules":['
      [ -n "$EXCLUDE_DOMAINS_BYPASS" ] && echo "{\"domain_keyword\":[${EXCLUDE_DOMAINS_BYPASS}],\"outbound\":\"proxy\"},"
      echo "{\"rule_set\":[${GEO_BYPASS_FORMAT}],\"outbound\":\"direct\"}"
      [ -z "$CIDR_PROXY" ] && echo "]," || \
      echo ",{\"source_ip_cidr\":[${CIDR_PROXY_FORMAT}],\"outbound\":\"proxy\"}],"
      echo "\"rule_set\":[$(gen_rule_sets "$GEO_BYPASS_LIST")]}}"
    } > "$tmpfile"

    mergeconf "$tmpfile"
  }

  add_all_rule_sets

  log "sing-box check config"
  sing-box check -c "$PATH_SINGBOX_CONFIG" >/dev/null 2>&1 || {
    log "sing-box config syntax error" && exit 1
  }

  log "sing-box format config"
  sing-box format -w -c "$PATH_SINGBOX_CONFIG" >/dev/null 2>&1 || {
    log "sing-box config formatting error" && exit 1
  }

  log "Launch sing-box"
  nohup sing-box run -c "$PATH_SINGBOX_CONFIG" \
    --disable-color > "$PATH_SINGBOX_LOG" 2>&1 &
}

# === CORE SERVICES ===
start_core() {
  log "---------------------- STARTING CORE -----------------------"

  # Due to some instances complaining about this, making sure its there every time.
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200
  chmod 600 /dev/net/tun

  # Actually starting WGDashboard
  log "Activating Python venv and executing the WireGuard Dashboard service."
  /bin/bash ./wgd.sh start
}

ensure_blocking() {
  # Wait a second before continuing, to give the python program some time to get ready.
  sleep 1s
  log "Ensuring container continuation."

  # Find and tail the latest error and access logs if they exist
  local logdir="${WGDASH}/src/log"

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

# Execute functions for the WireGuard Dashboard services, then set the environment variables
ensure_installation
set_envvars
start_sing_box
start_core
ensure_blocking
