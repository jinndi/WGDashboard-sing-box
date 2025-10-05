#!/bin/bash
# shellcheck disable=SC1091

. /scripts/utils.sh

# Paths
WGD="$WGDASH"
WGD_PID="${WGD}/gunicorn.pid"
WGD_PY_CACHE="${WGD}/__pycache__"
WGD_CONFIG="${WGD}/wg-dashboard.ini"
WGD_DB="${WGD}/db"
WGD_LOG="${WGD}/log"
WGD_DATA="/data"
WGD_DATA_CONFIG="${WGD_DATA}/wg-dashboard.ini"
WGD_DATA_DB="$WGD_DATA/db"
WARP_ENDPOINT="${WGD_DATA}/warp/endpoint"
HOSTS_FILE="/opt/hosts"
ADGUARD_SRS="${WGD_DATA}/adguard-filter-list.srs"
SINGBOX_CONFIG="${WGD_DATA}/singbox.json"
SINGBOX_ERR_LOG="${WGD_LOG}/singbox_err.log"
SINGBOX_CACHE="${WGD_DATA_DB}/singbox.db"
SINGBOX_TUN_NAME="${SINGBOX_TUN_NAME-singbox}"

# Global vars
PROXY_OUTBOUND=""
DIRECT_TAG="direct"

trap 'stop_service' SIGTERM
stop_service() {
  local checkPIDExist gunicorn_pid

  log "Stopping WGDashboard..."

	if [ -f "$WGD_PID" ]; then
    checkPIDExist=1
    while [ $checkPIDExist -eq 1 ]
    do
      if [ -f "$WGD_PID" ]; then
        gunicorn_pid=$(cat "$WGD_PID")
        log "Stopping WGDashboard Gunicorn on PID $gunicorn_pid"
        sudo kill "$gunicorn_pid"
      else
        checkPIDExist=0
      fi
      sleep 2
    done
    log "WGDashboard is stopped."
	else
		pkill -f "python3 dashboard.py"
	fi

  exit 0
}

validation_options() {
  if is_domain "$WGD_HOST" || is_ipv4 "$WGD_HOST"; then
    log "WGD_HOST accept: $WGD_HOST"
  else
    local public_ip
    public_ip="$(get_public_ipv4)"
    [ -z "$public_ip" ] && exiterr "WGD_HOST not set"
    warn "WGD_HOST set by default on ${public_ip}"
    WGD_HOST="${public_ip}"
  fi

  if is_port "$WGD_PORT"; then
    log "WGD_PORT accept: $WGD_PORT"
  else
    warn "WGD_PORT set by default on: 10086"
    WGD_PORT="10086"
  fi

  if is_ipv4 "$DNS_CLIENTS"; then
    log "DNS_CLIENTS accept: $DNS_CLIENTS"
  else
    warn "DNS_CLIENTS set by default on: 1.1.1.1"
    DNS_CLIENTS="1.1.1.1"
  fi

  . /scripts/dns-params-parser.sh "DNS_DIRECT" "$DNS_DIRECT" "https://common.dot.dns.yandex.net"

  . /scripts/dns-params-parser.sh "DNS_PROXY" "$DNS_PROXY" "tls://one.one.one.one"

  if [[ -z "$DNS_PROXY_TTL" ]]; then
    warn "DNS_PROXY_TTL set by default on: 300"
    DNS_PROXY_TTL="300"
  else
    if ((DNS_PROXY_TTL >= 0 && DNS_PROXY_TTL <= 600)); then
      log "DNS_PROXY_TTL accept: $DNS_PROXY_TTL"
    else
      warn "DNS_PROXY_TTL set by default on: 300"
      DNS_PROXY_TTL="300"
    fi
  fi

  ALLOW_FORWARD=${ALLOW_FORWARD:-}
  if [[ -n "$ALLOW_FORWARD" ]]; then
    validate_tun_list() {
      local list="$1"
      IFS=',' read -ra arr <<< "$list"
      for name in "${arr[@]}"; do
        if ! is_valid_tun_name "$name"; then
          warn "Invalid interface name: $name"
          return 1
        fi
      done
      return 0
    }
    if validate_tun_list "$ALLOW_FORWARD"; then
      log "ALLOW_FORWARD accept"
    else
      exiterr "ALLOW_FORWARD must be a valid"
    fi
  fi

  case "$ENABLE_ADGUARD" in
    true|false)
      log "ENABLE_ADGUARD accept"
    ;;
    *)
      warn "ENABLE_ADGUARD set by default on: false"
      ENABLE_ADGUARD="false"
    ;;
  esac

  if [[ -n "$PROXY_LINK" ]]; then
    if ! echo "$PROXY_LINK" | grep -qiE '^(vless://|ss://|socks5://)'; then
      exiterr "PROXY_LINK does NOT start with vless:// ss:// or socks5://"
    else
      . /scripts/proxy-link-parser.sh
    fi
  else
    PROXY_LINK=""
    warn "PROXY set by default on: WARP"
  fi

  if [[ -n "$PROXY_CIDR" ]]; then
    validate_cidr_list() {
      local list="$1"
      IFS=',' read -ra arr <<< "$list"
      for cidr in "${arr[@]}"; do
        if ! is_ipv4_cidr "$cidr"; then
          warn "PROXY_CIDR invalid: $cidr"
          return 1
        fi
      done
      return 0
    }
    if validate_cidr_list "$PROXY_CIDR"; then
      log "PROXY_CIDR accept"
    else
      exiterr "PROXY_CIDR must be a valid"
    fi
  else
    PROXY_CIDR="10.10.10.0/24"
    warn "PROXY_CIDR set by default on: 10.10.10.0/24"
  fi

  case "$WARP_OVER_PROXY" in
    true|false)
      log "WARP_OVER_PROXY accept"
    ;;
    *)
      warn "WARP_OVER_PROXY set by default on: false"
      WARP_OVER_PROXY="false"
    ;;
  esac

  case "$WARP_OVER_DIRECT" in
    true|false)
      log "WARP_OVER_DIRECT accept"
    ;;
    *)
      warn "WARP_OVER_DIRECT set by default on: false"
      WARP_OVER_DIRECT="false"
    ;;
  esac

  if [[ -n "$GEOSITE_BYPASS" ]]; then
    GEOSITE_BYPASS="${GEOSITE_BYPASS,,}"
    is_valid_geosite() {
      local s="$1"
      [[ $s =~ ^[a-z0-9@!-]+$ ]]
    }
    validate_geosite_list() {
      local list="$1"
      IFS=',' read -ra arr <<< "$list"
      for s in "${arr[@]}"; do
        if ! is_valid_geosite "$s"; then
          warn "Invalid geosite name: $s"
          return 1
        fi
      done
      return 0
    }
    if validate_geosite_list "$GEOSITE_BYPASS"; then
      log "GEOSITE_BYPASS accept"
    else
      exiterr "GEOSITE_BYPASS must be a valid"
    fi
  fi

  if [[ -n "$GEOIP_BYPASS" ]]; then
    GEOIP_BYPASS="${GEOIP_BYPASS,,}"
    is_valid_geoip() {
      local s="$1"
      [[ $s =~ ^[a-z]+$ ]]
    }
    validate_geoip_list() {
      local list="$1"
      IFS=',' read -ra arr <<< "$list"
      for s in "${arr[@]}"; do
        if ! is_valid_geoip "$s"; then
          warn "Invalid geoip name: $s"
          return 1
        fi
      done
      return 0
    }
    if validate_geoip_list "$GEOIP_BYPASS"; then
      log "GEOIP_BYPASS accept"
    else
      exiterr "GEOIP_BYPASS must be a valid"
    fi
  fi

  if [[ -n "$GEO_NO_DOMAINS" ]]; then
    # ASCII + punycode
    is_valid_ascii_domain() {
      local d="$1"
      [[ $d =~ ^([a-zA-Z0-9]([a-z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$ ]] || return 1
      (( ${#d} <= 253 )) || return 1
      return 0
    }
    convert_domains() {
      local list="$1"
      local result=()
      IFS=',' read -ra arr <<< "$list"

      for d in "${arr[@]}"; do
        d=$(echo "$d" | xargs)
        puny=$(idn2 "$d" 2>/dev/null) || { warn "GEO_NO_DOMAINS puny invalid domain: $d" >&2; continue; }
        if is_valid_ascii_domain "$puny"; then
          result+=("$puny")
        else
          warn "GEO_NO_DOMAINS ascii invalid domain: $d" >&2
        fi
      done
      (IFS=','; echo "${result[*]}")
    }
    GEO_NO_DOMAINS=$(convert_domains "$GEO_NO_DOMAINS")
  fi

  LOG_LEVEL="${LOG_LEVEL-fatal}"
  LOG_LEVEL="${LOG_LEVEL,,}"
  case "$LOG_LEVEL" in
    trace|debug|info|warn|error|fatal|panic)
      log "LOG_LEVEL accept"
    ;;
    *)
      warn "LOG_LEVEL set by default on 'fatal'"
      LOG_LEVEL="fatal"
    ;;
  esac
  case $LOG_LEVEL in
    trace|debug) WGD_LOG_LEVEL="DEBUG" ;;
    info) WGD_LOG_LEVEL="INFO" ;;
    warn) WGD_LOG_LEVEL="WARNING" ;;
    error) WGD_LOG_LEVEL="ERROR" ;;
    *) WGD_LOG_LEVEL="CRITICAL" ;;
  esac

  echo "------------------------------------------------------------"
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
}

set_envvars() {
  if [[ ! -s "${WGD_DATA_CONFIG}" ]]; then
    log "Config file is empty. Creating [Peers] section."
    {
      echo "[Peers]"
      echo "peer_global_dns = ${DNS_CLIENTS}"
      echo "remote_endpoint = ${WGD_HOST}"
      echo
      echo "[Server]"
      echo "app_port = ${WGD_PORT}"
      echo "app_prefix = /"
      echo "log_level = ${WGD_LOG_LEVEL}"
    } > "${WGD_DATA_CONFIG}"
    return 0
  else
    log "Config file is not empty, using pre-existing."
  fi

  set_envvar() {
    local var_name="$1"
    local var_value="$2"
    if grep -q "^${var_name} =" "$WGD_DATA_CONFIG"; then
      sed -i "s|^${var_name} = .*|${var_name} = ${var_value}|" "$WGD_DATA_CONFIG"
    fi
  }

  log "Verifying current variables..."

  check_and_update_var() {
    local var_name="$1"
    local var_value="$2"
    local current_value
    current_value=$(grep "^${var_name} = " "$WGD_DATA_CONFIG" | awk '{print $NF}')

    if [[ "$var_value" == "$current_value" ]]; then
      log "${var_name} is set correctly, moving on."
    else
      log "Changing default ${var_name}..."
      set_envvar "$var_name" "$var_value"
    fi
  }

  check_and_update_var "app_prefix" "/"
  check_and_update_var "remote_endpoint" "${WGD_HOST}"
  check_and_update_var "app_port" "${WGD_PORT}"
  check_and_update_var "log_level" "${WGD_LOG_LEVEL}"
  check_and_update_var "peer_global_dns" "${DNS_CLIENTS}"
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

inicialize_adguard(){
  # Checking whether the file exists and is not older than 3 hours (10,800 seconds)
  if [[ -f "$ADGUARD_SRS" ]] && [[ $(($(date +%s) - $(stat -c %Y "$ADGUARD_SRS"))) -lt 10800 ]]; then
    log "AdGuard filter list is up-to-date, skipping download"
    return 0
  fi

  mv "$ADGUARD_SRS" "${ADGUARD_SRS}.old" 2>/dev/null || true

  log "Downloading AdGuard filter list"
  if ! curl -fsSL -o "$ADGUARD_SRS" https://github.com/jinndi/adguard-filter-list-srs/blob/main/adguard-filter-list.srs?raw=true; then
    warn "Failed to download AdGuard filter list"
    [[ -f "${ADGUARD_SRS}.old" ]] && mv "${ADGUARD_SRS}.old" "$ADGUARD_SRS" 2>/dev/null || ENABLE_ADGUARD=false
    return 1
  fi
  rm -f "${ADGUARD_SRS}.old" 2>/dev/null || true
}

start_sing_box() {
  local proxy_cidr_format geo_no_domains_format geo_bypass_list geo_bypass_format

  proxy_cidr_format="\"${PROXY_CIDR//,/\",\"}\""

  [ -n "$GEO_NO_DOMAINS" ] && geo_no_domains_format="\"${GEO_NO_DOMAINS//,/\",\"}\""
  [ -n "$GEOSITE_BYPASS" ] && geo_bypass_list="geosite-${GEOSITE_BYPASS//,/\,geosite-}"
  [[ -n "$GEOSITE_BYPASS" && -n "$GEOIP_BYPASS" ]] && geo_bypass_list+=","
  [ -n "$GEOIP_BYPASS" ] && geo_bypass_list+="geoip-${GEOIP_BYPASS//,/\,geoip-}"
  geo_bypass_format="\"${geo_bypass_list//,/\",\"}\""

  gen_dns_servers(){
    local detour_proxy="proxy"
    local direct_path proxy_path
    local output=()
    [[ -f "$WARP_ENDPOINT" && "$WARP_OVER_PROXY" == "true" ]] && detour_proxy="proxy1"
    if [[ "$DNS_DIRECT_TYPE" == "local" ]]; then
      output+=("{\"tag\":\"dns-direct\",\"type\":\"local\"}")
    else
      [[ "$DNS_DIRECT_TYPE" == "https" ]] && direct_path="\"path\":\"${DNS_DIRECT_PATH}\","
      output+=("{\"tag\":\"dns-direct\",\"type\":\"${DNS_DIRECT_TYPE}\",
        \"server\":\"${DNS_DIRECT_SERVER}\",\"server_port\":${DNS_DIRECT_SERVER_PORT},
        ${direct_path}\"domain_resolver\":\"dns-domain-resolver\"
      }")
    fi
    if [[ -f "$WARP_ENDPOINT" || -n "$PROXY_LINK" ]]; then
      if [[ "$DNS_PROXY_TYPE" == "local" ]]; then
        output+=("{\"tag\":\"dns-proxy\",\"type\":\"local\",\"detour\":\"${detour_proxy}\"}")
      else
        [[ "$DNS_PROXY_TYPE" == "https" ]] && proxy_path="\"path\":\"${DNS_PROXY_PATH}\","
        output+=("{\"tag\":\"dns-proxy\",\"type\":\"${DNS_PROXY_TYPE}\",
          \"server\":\"${DNS_PROXY_SERVER}\",\"server_port\":${DNS_PROXY_SERVER_PORT},
          ${proxy_path}\"domain_resolver\":\"dns-domain-resolver\",\"detour\":\"${detour_proxy}\"
        }")
      fi
    fi
    [ -f "$HOSTS_FILE" ] && output+=("{\"tag\":\"dns-hosts\",\"type\":\"hosts\",\"path\":\"${HOSTS_FILE}\"}")
    output+=("{\"tag\":\"dns-domain-resolver\",\"type\":\"local\"}")
    IFS=','; echo "${output[*]}"
  }

  gen_dns_rules(){
    local output=()
    [ -f "$HOSTS_FILE" ] && output+=('{"ip_accept_any":true,"server":"dns-hosts"}')
    [[ "$ENABLE_ADGUARD" == "true" ]] && output+=('{"rule_set":["adguard"],"action":"reject"}')
    if [[ -f "$WARP_ENDPOINT" || -n "$PROXY_LINK" ]]; then
      [[ -n "$GEOSITE_BYPASS" || -n "$GEOIP_BYPASS" ]] && \
      output+=("{\"rule_set\":[${geo_bypass_format}],\"server\":\"dns-direct\"}")
      output+=("{\"source_ip_cidr\":[${proxy_cidr_format}],\"server\":\"dns-proxy\",\"rewrite_ttl\":${DNS_PROXY_TTL}}")
    fi
    IFS=','; echo "${output[*]}"
  }

  gen_warp_endpoints(){
    local is_warp_proxy=0
    if [[ -f "$WARP_ENDPOINT" && -z "$PROXY_LINK" ]]; then
      is_warp_proxy=1
      cat "$WARP_ENDPOINT"
    elif [[ -f "${WARP_ENDPOINT}.over_proxy" && "$WARP_OVER_PROXY" == "true" ]]; then
      is_warp_proxy=1
      cat "${WARP_ENDPOINT}.over_proxy"
    fi
    if [[ -f "${WARP_ENDPOINT}.over_direct" && "$WARP_OVER_DIRECT" == "true" ]]; then
      [[ "${is_warp_proxy:-0}" -eq 1 ]] && echo ','
      cat "${WARP_ENDPOINT}.over_direct"
    fi
  }

  gen_outbounds(){
    local output=()
    if [[ -f "${WARP_ENDPOINT}.over_direct" && "$WARP_OVER_DIRECT" == "true" ]]; then
      DIRECT_TAG="direct1"
    fi
    output+=("{\"tag\":\"${DIRECT_TAG}\",\"type\":\"direct\"}" "${PROXY_OUTBOUND}")
    IFS=','; echo "${output[*]}"
  }

  gen_route_rules(){
    local output=()
    output+=('
    {"action":"sniff"},
    {"type":"logical","mode":"or","rules":[{"protocol":"dns"},{"port":53}],"action":"hijack-dns"},
    {"ip_is_private":true,"outbound":"direct"}
    ')
    [[ "$ENABLE_ADGUARD" == "true" ]] && output+=('{"rule_set":["adguard"],"action":"reject"}')
    if [[ -f "$WARP_ENDPOINT" || -n "$PROXY_LINK" ]]; then
      [ -n "$GEO_NO_DOMAINS" ] && [[ -n "$GEOSITE_BYPASS" || -n "$GEOIP_BYPASS" ]] && \
      output+=("{\"domain_suffix\":[${geo_no_domains_format}],\"outbound\":\"proxy\"}")
      [[ -n "$GEOSITE_BYPASS" || -n "$GEOIP_BYPASS" ]] && \
      output+=("{\"rule_set\":[${geo_bypass_format}],\"outbound\":\"direct\"}")
      output+=("{\"source_ip_cidr\":[${proxy_cidr_format}],\"outbound\":\"proxy\"}")
    fi
    IFS=','; echo "${output[*]}"
  }

  gen_rule_sets() {
    local rules="$1"
    local rule base_url
    local output=()
    local download_detour="proxy"
    [[ ! -f "$WARP_ENDPOINT" && -z "$PROXY_LINK" ]] && download_detour="direct"
    IFS=',' read -ra entries <<< "$rules"
    for rule in "${entries[@]}"; do
      base_url="https://raw.githubusercontent.com/SagerNet/sing-${rule%%-*}/rule-set/${rule}.srs"
      output+=("{\"tag\":\"${rule}\",\"type\":\"remote\",\"format\":\"binary\",\"url\":\"${base_url}\",\"download_detour\":\"$download_detour\",\"update_interval\":\"1d\"}")
    done
    IFS=','; echo "${output[*]}"
  }

  gen_route_rule_set(){
    local output=()
    [[ -n "$GEOSITE_BYPASS" || -n "$GEOIP_BYPASS" ]] && \
    output+=("$(gen_rule_sets "$geo_bypass_list")")
    [[ "$ENABLE_ADGUARD" == "true" ]] && \
    output+=("{\"type\":\"local\",\"tag\":\"adguard\",\"format\":\"binary\",\"path\":\"${ADGUARD_SRS}\"}")
    IFS=','; echo "${output[*]}"
  }

  log "sing-box creating config"

cat << EOF > "$SINGBOX_CONFIG"
{
  "log": {"disabled": false, "level": "$LOG_LEVEL", "timestamp": true},
  "dns": {
    "servers": [$(gen_dns_servers)],
    "rules": [$(gen_dns_rules)],
    "final": "dns-direct",
    "strategy": "prefer_ipv4",
    "independent_cache": true
  },
  "inbounds": [
    {
      "tag": "tun-in", "type": "tun", "interface_name": "${SINGBOX_TUN_NAME}",
      "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"], "auto_route": true,
      "auto_redirect": true, "strict_route": true, "stack": "system", "mtu": 9000
    }
  ],
  "endpoints": [$(gen_warp_endpoints)],
  "outbounds": [$(gen_outbounds)],
  "route": {
    "rules": [$(gen_route_rules)],
    "rule_set": [$(gen_route_rule_set)],
    "final": "direct",
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-domain-resolver"
  },
  "experimental": {
    "cache_file": {"enabled": true, "path": "${SINGBOX_CACHE}"}
  }
}
EOF

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
  log "Activating Python venv and executing the WireGuard Dashboard service."
  . ./venv/bin/activate
  sudo ./venv/bin/gunicorn --config ./gunicorn.conf.py
  sleep 2

  local checkPIDExist=0
  while [ $checkPIDExist -eq 0 ]
  do
    if [[ -f "$WGD_PID" ]]; then
      checkPIDExist=1
      log "Checking if WGDashboard Gunicorn started successfully"
    fi
    sleep 2
  done
  log "WGDashboard Gunicorn started successfully"

  log "Apply iptables forwards"
  . /scripts/auto-iptables-forward.sh
}

ensure_blocking() {
  sleep 1
  log "Ensuring container continuation."

  local latest_wgd_err_log
  latest_wgd_err_log=$(find "$WGD_LOG" -name "error_*.log" -type f -print | sort -r | head -n 1)

  if [[ -n "$SINGBOX_ERR_LOG" ]]; then
    log "Tailing logs\n"
    tail -f "$latest_wgd_err_log" "$SINGBOX_ERR_LOG"
    wait $!
  else
    exiterr "No log files found to tail. Something went wrong, exiting..."
  fi
}

echo -e "\n------------------------- START ----------------------------"
validation_options
ensure_installation

echo -e "\n-------------- SETTING ENVIRONMENT VARIABLES ---------------"
set_envvars

echo -e "\n------------------ NETWORK OPTIMIZATION --------------------"
network_optimization

[[ "$ENABLE_ADGUARD" == "true" ]] && \
echo -e "\n------------------ INITIALIZE ADGUARD ----------------------" \
&& inicialize_adguard

echo -e "\n-------------------- STARTING SING-BOX ---------------------"
start_sing_box

echo -e "\n---------------------- STARTING CORE -----------------------"
start_core

echo -e "\n------------------------ SHOW LOGS -------------------------"
ensure_blocking
