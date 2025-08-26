#!/bin/bash
# shellcheck disable=SC1091

log(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

exiterr(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") ❌ Error: $1"
  exit 1
}

WGD="$WGDASH/src" # WGDASH=/opt/wgdashboard
WGD_PID="${WGD}/gunicorn.pid"
WGD_PY_CACHE="${WGD}/__pycache__"
WGD_CONFIG="${WGD}/wg-dashboard.ini"
WGD_DB="${WGD}/db"
WGD_LOG="${WGD}/log"

WGD_DATA="/data"
WGD_DATA_CONFIG="${WGD_DATA}/wg-dashboard.ini"
WGD_DATA_DB="$WGD_DATA/db"

SINGBOX_CONFIG="${WGD_DATA}/singbox.json"
SINGBOX_ERR_LOG="${WGD_LOG}/singbox_err.log"
SINGBOX_CACHE="${WGD_DATA_DB}/singbox.db"
SINGBOX_TUN_NAME="singbox"

DNS_DIRECT="${DNS_DIRECT:-77.88.8.8}"

PROXY_INBOUND=""

[ -n "$PROXY_LINK" ] && {
  source /proxy-link-parser.sh "$PROXY_LINK"
  DNS_PROXY="${DNS_PROXY:-1.1.1.1}"
  CIDR_PROXY="${CIDR_PROXY:-10.10.10.0/24}"
  GEOSITE_BYPASS="${GEOSITE_BYPASS:-}"
  GEOIP_BYPASS="${GEOIP_BYPASS:-}"
  GEO_NO_DOMAINS="${GEO_NO_DOMAINS:-}"
}

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
}

set_envvars() {
  local current_dns current_public_ip default_ip current_wgd_port current_app_prefix
  local app_prefix="${WGD_PATH-}"
  local public_ip="${WGD_HOST:-}"
  local wgd_port="${WGD_PORT:-10086}"
  local global_dns="${DNS_CLIENTS:-1.1.1.1}"

  if [ ! -s "${WGD_DATA_CONFIG}" ]; then
    log "Config file is empty. Creating [Peers] section."
    {
      echo "[Peers]"
      echo "peer_global_dns = ${global_dns}"
      echo "remote_endpoint = ${public_ip}"
      echo -e "\n[Server]"
      echo "app_port = ${wgd_port}"
      echo "app_prefix = /${app_prefix}"
    } > "${WGD_DATA_CONFIG}"
  else
    log "Config file is not empty, using pre-existing."
  fi

  log "Verifying current variables..."

  current_dns=$(grep "peer_global_dns = " "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [ "${global_dns}" == "$current_dns" ]; then
    log "DNS is set correctly, moving on."
  else
    log "Changing default DNS..."
    sed -i "s/^peer_global_dns = .*/peer_global_dns = ${global_dns}/" "$WGD_DATA_CONFIG"
  fi

  current_public_ip=$(grep "remote_endpoint = " "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [ "${public_ip}" == "" ]; then
    default_ip=$(curl -s ifconfig.me)
    [ -z "$default_ip" ] && public_ip=$(curl -s https://api.ipify.org)
    [ -z "$default_ip" ] && exiterr "Not set 'WGD_HOST' var"

    log "Trying to fetch the Public-IP using curl: ${default_ip}"
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${default_ip}/" "$WGD_DATA_CONFIG"
  elif [ "${current_public_ip}" != "${public_ip}" ]; then
    sed -i "s/^remote_endpoint = .*/remote_endpoint = ${public_ip}/" "$WGD_DATA_CONFIG"
  else
    log "Public-IP is correct, moving on."
  fi

  current_wgd_port=$(grep "app_port = " "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [ "${current_wgd_port}" == "${wgd_port}" ]; then
    log "Current WGD port is set correctly, moving on."
  else
    log "Changing default WGD port..."
    sed -i "s/^app_port = .*/app_port = ${wgd_port}/" "$WGD_DATA_CONFIG"
  fi

  current_app_prefix=$(grep "app_prefix =" "$WGD_DATA_CONFIG" | awk '{print $NF}')
  if [ "${current_app_prefix}" == "/${app_prefix}" ]; then
    log "Current WGD app_prefix is set correctly, moving on."
  else
    log "Changing default WGD UI_BASE_PATH..."
    sed -i "s|^app_prefix = .*|app_prefix = /${app_prefix}|" "$WGD_DATA_CONFIG"
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

cat << EOF > "$SINGBOX_CONFIG"
{
  "log": {"level": "error", "timestamp": true},
  "dns": {
    "servers": [
      {"tag": "dns-direct", "type": "https", "server": "${DNS_DIRECT}", "detour": "direct"},
      {"tag": "dns-proxy", "type": "https", "server": "${DNS_PROXY}", "detour": "proxy"}
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
  "outbounds": [
    {"tag": "direct", "type": "direct", "domain_resolver": "dns-direct"}
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
      rm -f "$tmpfile" "$tmpout"
      exiterr "sing-box merge config error"
    fi

    mv "$tmpout" "$SINGBOX_CONFIG"
    rm -f "$tmpfile"
  }

  add_all_rule_sets() {
    [[ -z "$PROXY_LINK" ]] && return

    local tmpfile

    log "sing-box add route rules"

    [ -n "$CIDR_PROXY" ] && cidr_proxy_format="\"${CIDR_PROXY//,/\",\"}\""

    if [ -z "$GEOSITE_BYPASS" ] && [ -z "$GEOIP_BYPASS" ]
    then
      [ -n "$CIDR_PROXY" ] && tmpfile=$(mktemp 2>/dev/null) && \
      {
        echo "{\"dns\":{\"rules\":[{\"source_ip_cidr\":[${cidr_proxy_format}],\"server\":\"dns-proxy\"}]},"
        echo "\"route\":{\"rules\":[{\"source_ip_cidr\":[${cidr_proxy_format}],\"outbound\":\"proxy\"}]}}"
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
      echo "{\"dns\":{\"rules\":[{\"rule_set\":[${geo_bypass_format}],\"server\":\"dns-direct\"}"
      [ -z "$CIDR_PROXY" ] && echo "]}," || echo ",{\"source_ip_cidr\":[${cidr_proxy_format}],\"server\":\"dns-proxy\"}]},"
      echo '"route":{"rules":['
      [ -n "$GEO_NO_DOMAINS" ] && echo "{\"domain_keyword\":[${GEO_NO_DOMAINS}],\"outbound\":\"proxy\"},"
      echo "{\"rule_set\":[${geo_bypass_format}],\"outbound\":\"direct\"}"
      [ -z "$CIDR_PROXY" ] && echo "]," || echo ",{\"source_ip_cidr\":[${cidr_proxy_format}],\"outbound\":\"proxy\"}],"
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
}

ensure_blocking() {
  sleep 3s
  log "Ensuring container continuation."
  local latest_wgd_err_log

  latest_wgd_err_log=$(find "$WGD_LOG" -name "error_*.log" -type f -print | sort -r | head -n 1)

  if [[ -n "$latest_wgd_err_log" && -n "$SINGBOX_ERR_LOG" ]]; then
    log "Tailing logs: $latest_wgd_err_log, $SINGBOX_ERR_LOG"
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
