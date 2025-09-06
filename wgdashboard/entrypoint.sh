#!/bin/bash
# shellcheck disable=SC1091

log(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

warn(){
  log "⚠️ WARN: $1"
}

exiterr(){
  log "❌ ERROR: $1"
  exit 1
}

WGD="$WGDASH/src" # WGDASH=/opt/wgdashboard
WGD_PID="${WGD}/gunicorn.pid"
WGD_PY_CACHE="${WGD}/__pycache__"
WGD_CONFIG="${WGD}/wg-dashboard.ini"
WGD_DB="${WGD}/db"
WGD_LOG="${WGD}/log"

WGD_HOST="${WGD_HOST:-}"
WGD_PORT="${WGD_PORT:-10086}"
WGD_PATH="${WGD_PATH-}"

DNS_CLIENTS="${DNS_CLIENTS:-1.1.1.1}"
DNS_DIRECT="${DNS_DIRECT:-77.88.8.8}"
DNS_PROXY="${DNS_PROXY:-1.1.1.1}"

ALLOW_FORWARD=${ALLOW_FORWARD:-}

PROXY_LINK="${PROXY_LINK:-}"
PROXY_CIDR="${PROXY_CIDR:-10.10.10.0/24}"
PROXY_INBOUND=""

GEOSITE_BYPASS="${GEOSITE_BYPASS:-}"
GEOIP_BYPASS="${GEOIP_BYPASS:-}"
GEO_NO_DOMAINS="${GEO_NO_DOMAINS:-}"

DIRECT_TAG="direct"

WARP_OVER_PROXY="${WARP_OVER_PROXY:-false}"
WARP_OVER_DIRECT="${WARP_OVER_DIRECT:-false}"

WGD_DATA="/data"
WGD_DATA_CONFIG="${WGD_DATA}/wg-dashboard.ini"
WGD_DATA_DB="$WGD_DATA/db"
WARP_ENDPOINT="${WGD_DATA}/warp/endpoint"

SINGBOX_CONFIG="${WGD_DATA}/singbox.json"
SINGBOX_ERR_LOG="${WGD_LOG}/singbox_err.log"
SINGBOX_CACHE="${WGD_DATA_DB}/singbox.db"
SINGBOX_TUN_NAME="${SINGBOX_TUN_NAME-singbox}"

trap 'stop_service' SIGTERM

stop_service() {
  log "[WGDashboard] Stopping WGDashboard..."
  /bin/bash ./wgd.sh stop
  exit 0
}

ensure_installation() {
  log "Quick-installing..."

  cd "${WGD}" || exit

  [ -f "$WGD_PID" ] && { log "Found stale pid, removing..."; rm "$WGD_PID"; }

  [ -d "$WGD_PY_CACHE" ] && { log "Directory __pycache__ exists. Deleting it..."; rm -rf "$WGD_PY_CACHE"; }

  [ -d "$WGD_DATA_DB" ] || { log "Creating database dir"; mkdir -p "$WGD_DATA_DB"; }
  [ -d "$WGD_DB" ] || { log "Linking database dir"; ln -s "$WGD_DATA_DB" "$WGD_DB"; }

  [ -f "$WGD_DATA_CONFIG" ] || { log "Creating wg-dashboard.ini file"; touch "$WGD_DATA_CONFIG"; }
  [ -f "$WGD_CONFIG" ] || { log "Linking wg-dashboard.ini file"; ln -s "$WGD_DATA_CONFIG" "$WGD_CONFIG"; }

  if [ ! -f "$WARP_ENDPOINT" ]; then
    if [[ -z "$PROXY_LINK" || "$WARP_OVER_PROXY" == "true"  || "$WARP_OVER_DIRECT" == "true" ]]; then
      log "Generate WARP endpoint"
      . /scripts/generate-warp-endpoint.sh
    fi
  fi

  if [ -n "$PROXY_LINK" ]; then
    log "Parse proxy link"
    . /scripts/proxy-link-parser.sh
  fi
}

set_envvars() {
  local current_dns current_public_ip default_ip current_wgd_port current_app_prefix

  if [[ ! -s "${WGD_DATA_CONFIG}" ]]; then
    log "Config file is empty. Creating [Peers] section."
    {
      echo "[Peers]"
      echo "peer_global_dns = ${DNS_CLIENTS}"
      echo "remote_endpoint = ${WGD_HOST}"
      echo -e "\n[Server]"
      echo "app_port = ${WGD_PORT}"
      echo "app_prefix = /${WGD_PATH}"
    } > "${WGD_DATA_CONFIG}"
    return 0
  else
    log "Config file is not empty, using pre-existing."
  fi

  log "Verifying current variables..."

  current_dns=$(grep "peer_global_dns = " "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [[ "${DNS_CLIENTS}" == "$current_dns" ]]; then
    log "DNS is set correctly, moving on."
  else
    log "Changing default DNS..."
    sed -i "s/^peer_global_dns = .*/peer_global_dns = ${DNS_CLIENTS}/" "$WGD_DATA_CONFIG"
  fi

  current_public_ip=$(grep "remote_endpoint = " "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [[ "${WGD_HOST}" == "" ]]; then
    default_ip=$(curl -s ifconfig.me)
    [ -z "$default_ip" ] && public_ip=$(curl -s https://api.ipify.org)
    [ -z "$default_ip" ] && exiterr "Not set 'WGD_HOST' var"

    log "Trying to fetch the Public-IP using curl: ${default_ip}"
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${default_ip}/" "$WGD_DATA_CONFIG"
  elif [[ "${current_public_ip}" != "${WGD_HOST}" ]]; then
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${public_ip}/" "$WGD_DATA_CONFIG"
  else
    log "Public-IP is correct, moving on."
  fi

  current_wgd_port=$(grep "app_port = " "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [[ "${current_wgd_port}" == "${WGD_PORT}" ]]; then
    log "Current WGD port is set correctly, moving on."
  else
    log "Changing default WGD port..."
    sed -i "s/^app_port = .*/app_port = ${WGD_PORT}/" "$WGD_DATA_CONFIG"
  fi

  current_app_prefix=$(grep "app_prefix =" "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [[ "${current_app_prefix}" == "/${WGD_PATH}" ]]; then
    log "Current WGD app_prefix is set correctly, moving on."
  else
    log "Changing default WGD UI_BASE_PATH..."
    sed -i "s|^app_prefix = .*|app_prefix = /${WGD_PATH}|" "$WGD_DATA_CONFIG"
  fi
}

network_optimization(){
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
  log "sing-box creating config"

  gen_dns(){
    echo "{\"tag\":\"dns-direct\",\"type\":\"https\",\"server\":\"${DNS_DIRECT}\",\"detour\":\"direct\"}"
    [[ -f "$WARP_ENDPOINT" || -n "$PROXY_LINK" ]] && \
    echo ",{\"tag\":\"dns-proxy\",\"type\":\"https\",\"server\":\"${DNS_PROXY}\",\"detour\":\"proxy\"}"
    [ -f "/opt/hosts" ] && echo ',{"type":"hosts","tag":"dns-hosts","path":"/opt/hosts"}'
  }

  get_warp_endpoint(){
    echo '"endpoints": ['
    if [[ -f "$WARP_ENDPOINT" && -z "$PROXY_LINK" ]]; then
      cat "$WARP_ENDPOINT"
    elif [[ -f "${WARP_ENDPOINT}.over_proxy" && "$WARP_OVER_PROXY" == "true" ]]; then
      cat "${WARP_ENDPOINT}.over_proxy"
    fi
    if [[ -f "${WARP_ENDPOINT}.over_direct" && "$WARP_OVER_DIRECT" == "true" ]]; then
      echo ','
      cat "${WARP_ENDPOINT}.over_direct"
    fi
    echo '],'
  }

  gen_rule_sets() {
    local download_detour="proxy"
    [[ ! -f "$WARP_ENDPOINT" && -z "$PROXY_LINK" ]] && download_detour="direct"

    local rules="$1"
    local first_rule=true

    IFS=',' read -ra entries <<< "$rules"
    for rule in "${entries[@]}"; do
      [ "$first_rule" = true ] && first_rule=false || echo ","
      local base_url="https://raw.githubusercontent.com/SagerNet/sing-${rule%%-*}/rule-set/${rule}.srs"
      echo "{\"tag\":\"${rule}\",\"type\":\"remote\",\"format\":\"binary\",\"url\":\"${base_url}\",
        \"download_detour\":\"$download_detour\",\"update_interval\":\"1d\"}"
    done
  }

  if [[ -f "${WARP_ENDPOINT}.over_direct" && "$WARP_OVER_DIRECT" == "true" ]]; then
    DIRECT_TAG="direct1"
  fi

cat << EOF > "$SINGBOX_CONFIG"
{
  "log": {"level": "error", "timestamp": true},
  "dns": {
    "servers": [
      $(gen_dns)
    ],
    "rules": [
      {"rule_set": "geosite-category-ads-all", "action": "reject"}
    ],
    "final": "dns-direct",
    "strategy": "prefer_ipv4"
  },
  "inbounds": [
    {
      "tag": "tun-in", "type": "tun", "interface_name": "${SINGBOX_TUN_NAME}",
      "address": ["172.18.0.1/30", "fd00:18::1/126"], "mtu": 1500, "auto_route": true,
      "auto_redirect": true, "strict_route": true, "stack": "system"
    }
  ],
  $(get_warp_endpoint)
  "outbounds": [
    {"tag": "${DIRECT_TAG}", "type": "direct", "domain_resolver": "dns-direct"}
    ${PROXY_INBOUND}
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
    "cache_file": {"enabled": true, "path": "${SINGBOX_CACHE}"}
  }
}
EOF

  mergeconf() {
    local tmpfile="$1"
    local tmpout
    tmpout=$(mktemp 2>/dev/null)

    if ! sing-box merge "$tmpout" \
      -c "$SINGBOX_CONFIG" -c "$tmpfile" \
      >/dev/null 2>&1;
    then
      warn "Merge config error, debug info:"
      cat "$tmpfile"
      rm -f "$tmpfile" "$tmpout"
      exiterr "sing-box merge config error"
    fi

    mv "$tmpout" "$SINGBOX_CONFIG"
    rm -f "$tmpfile"
  }

  add_all_rule_sets() {
    [[ ! -f "$WARP_ENDPOINT" && -z "$PROXY_LINK" ]] && return

    local tmpfile proxy_cidr_format

    log "sing-box add route rules"

    proxy_cidr_format="\"${PROXY_CIDR//,/\",\"}\""

    if [[ -z "$GEOSITE_BYPASS" && -z "$GEOIP_BYPASS" ]]
    then
      tmpfile=$(mktemp 2>/dev/null) && \
      {
        echo '{"dns":{"rules":['
        [ -f "/opt/hosts" ] && echo '{"ip_accept_any":true,"server":"dns-hosts"},'
        echo "{\"source_ip_cidr\":[${proxy_cidr_format}],\"server\":\"dns-proxy\"}]},"
        echo "\"route\":{\"rules\":[{\"source_ip_cidr\":[${proxy_cidr_format}],\"outbound\":\"proxy\"}]}}"
      } > "$tmpfile" && mergeconf "$tmpfile"
      return
    fi

    tmpfile=$(mktemp 2>/dev/null)

    local geo_bypass_list geo_bypass_format

    [ -n "$GEO_NO_DOMAINS" ] && GEO_NO_DOMAINS="\"${GEO_NO_DOMAINS//,/\",\"}\""
    [ -n "$GEOSITE_BYPASS" ] && geo_bypass_list="geosite-${GEOSITE_BYPASS//,/\,geosite-}"
    [ -n "$GEOSITE_BYPASS" ] && [ -n "$GEOIP_BYPASS" ] && geo_bypass_list+=","
    [ -n "$GEOIP_BYPASS" ] && geo_bypass_list+="geoip-${GEOIP_BYPASS//,/\,geoip-}"
    geo_bypass_format="\"${geo_bypass_list//,/\",\"}\""

    {
      echo '{"dns":{"rules":['
      [ -f "/opt/hosts" ] && echo '{"ip_accept_any":true,"server":"dns-hosts"},'
      echo "{\"rule_set\":[${geo_bypass_format}],\"server\":\"dns-direct\"},"
      echo "{\"source_ip_cidr\":[${proxy_cidr_format}],\"server\":\"dns-proxy\"}]},"
      echo '"route":{"rules":['
      [ -n "$GEO_NO_DOMAINS" ] && echo "{\"domain_keyword\":[${GEO_NO_DOMAINS}],\"outbound\":\"proxy\"},"
      echo "{\"rule_set\":[${geo_bypass_format}],\"outbound\":\"direct\"},"
      echo "{\"source_ip_cidr\":[${proxy_cidr_format}],\"outbound\":\"proxy\"}],"
      echo "\"rule_set\":[$(gen_rule_sets "$geo_bypass_list")]}}"
    } > "$tmpfile"

    mergeconf "$tmpfile"
  }

  add_all_rule_sets

  log "sing-box check config"
  sing-box check -c "$SINGBOX_CONFIG" >/dev/null 2>&1 || {
    exiterr "sing-box config syntax error"
  }

  log "sing-box format config"
  sing-box format -w -c "$SINGBOX_CONFIG" >/dev/null 2>&1 || {
    exiterr "sing-box config formatting error"
  }

  log "Launch sing-box"

  if [ ! -c /dev/net/tun ]; then
    log "Creating /dev/net/tun"
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 0666 /dev/net/tun
  fi
  modprobe tun 2>/dev/null || true

  nohup sing-box run -c "$SINGBOX_CONFIG" \
    --disable-color > "$SINGBOX_ERR_LOG" 2>&1 &
}

start_core() {
  # Actually starting WGDashboard
  log "Activating Python venv and executing the WireGuard Dashboard service."
  /bin/bash ./wgd.sh start
  . /scripts/auto-iptables-forward.sh
}

ensure_blocking() {
  sleep 1s
  log "Ensuring container continuation."
  local latest_wgd_err_log

  latest_wgd_err_log=$(find "$WGD_LOG" -name "error_*.log" -type f -print | sort -r | head -n 1)

  if [[ -n "$latest_wgd_err_log" && -n "$SINGBOX_ERR_LOG" ]]; then
    log "Tailing logs\n"
    tail -f "$latest_wgd_err_log" "$SINGBOX_ERR_LOG"
    wait $!
  else
    exiterr "No log files found to tail. Something went wrong, exiting..."
  fi
}

echo -e "\n------------------------- START ----------------------------"
ensure_installation

echo -e "\n-------------- SETTING ENVIRONMENT VARIABLES ---------------"
set_envvars

echo -e "\n------------------ NETWORK OPTIMIZATION --------------------"
network_optimization

echo -e "\n-------------------- STARTING SING-BOX ---------------------"
start_sing_box

echo -e "\n---------------------- STARTING CORE -----------------------"
start_core

echo -e "\n------------------------ SHOW LOGS -------------------------"
ensure_blocking
