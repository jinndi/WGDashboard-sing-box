#!/bin/bash
# shellcheck disable=SC1091

# Load utils
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
SINGBOX_ERR_LOG="${WGD_LOG}/singbox.log"
SINGBOX_CACHE="${WGD_DATA_DB}/singbox.db"
SINGBOX_TUN_NAME="${SINGBOX_TUN_NAME-singbox}"

SINGBOX_PID=""
GUNICORN_PID=""

validation_options(){
  log "Validating options..."

  if is_domain "${WGD_PORT:-}" || is_ip "${WGD_PORT:-}"; then
    log "WGD_HOST accept: ${WGD_HOST}"
  else
    local public_ip
    public_ip="$(get_public_ipv4)"
    [ -z "$public_ip" ] && exiterr "WGD_HOST not set"
    warn "WGD_HOST set by default on: ${public_ip}"
    WGD_HOST="${public_ip}"
  fi

  if is_port "${WGD_PORT:-}"; then
    log "WGD_PORT accept: ${WGD_PORT}"
  else
    warn "WGD_PORT set by default on: 10086"
    WGD_PORT="10086"
  fi

  case "${LOG_LEVEL:-}" in
    trace|debug|info|warn|error|fatal|panic)
      log "LOG_LEVEL accept: ${LOG_LEVEL}"
    ;;
    *)
      warn "LOG_LEVEL set by default on 'fatal'"
      LOG_LEVEL="fatal"
    ;;
  esac
  case "$LOG_LEVEL" in
    trace|debug) WGD_LOG_LEVEL="DEBUG" ;;
    info) WGD_LOG_LEVEL="INFO" ;;
    warn) WGD_LOG_LEVEL="WARNING" ;;
    error) WGD_LOG_LEVEL="ERROR" ;;
    *) WGD_LOG_LEVEL="CRITICAL" ;;
  esac

  DNS_DIRECT="${DNS_DIRECT:-}"
  . /scripts/dns-params-parser.sh "DNS_DIRECT" "$DNS_DIRECT" "https://dns.google"
  DNS_PROXY="${DNS_PROXY-}"
  . /scripts/dns-params-parser.sh "DNS_PROXY" "$DNS_PROXY" "tls://one.one.one.one"

  DNS_PROXY_TTL="${DNS_PROXY_TTL:-}"
  if ((DNS_PROXY_TTL >= 0 && DNS_PROXY_TTL <= 600)); then
    log "DNS_PROXY_TTL accept: ${DNS_PROXY_TTL}"
  else
    warn "DNS_PROXY_TTL set by default on: 300"
    DNS_PROXY_TTL="300"
  fi

  if [[ -n "${ALLOW_FORWARD:-}" ]]; then
    if validate_tun_list "$ALLOW_FORWARD"; then
      log "ALLOW_FORWARD accept: ${ALLOW_FORWARD}"
    else
      exiterr "ALLOW_FORWARD must be a valid"
    fi
  fi

  case "${ENABLE_ADGUARD:-}" in
    true|false)
      log "ENABLE_ADGUARD accept: ${ENABLE_ADGUARD}"
    ;;
    *)
      warn "ENABLE_ADGUARD set by default on: false"
      ENABLE_ADGUARD="false"
    ;;
  esac

  if [[ -n "${BLOCK_GEOSITE:-}" ]]; then
    BLOCK_GEOSITE="${BLOCK_GEOSITE,,}"
    if validate_geosite_name_rules "$BLOCK_GEOSITE"; then
      log "BLOCK_GEOSITE accept: ${BLOCK_GEOSITE:0:5}....."
    else
      exiterr "BLOCK_GEOSITE must be a valid"
    fi
  fi

  if [[ -n "${BLOCK_GEOIP:-}" ]]; then
    BLOCK_GEOIP="${BLOCK_GEOIP,,}"
    if validate_geoip_name_rules "$BLOCK_GEOIP"; then
      log "BLOCK_GEOIP accept: ${BLOCK_GEOIP:0:5}....."
    else
      exiterr "BLOCK_GEOIP must be a valid"
    fi
  fi

  if [[ -n "${BLOCK_SITES:-}" ]]; then
    BLOCK_SITES=$(convert_domains "$BLOCK_SITES")
  fi

  if [[ -n "${PROXY_LINK:-}" ]]; then
    PROXY_OUTBOUND=""
    PROXY_ENDPOINT=""
    . /scripts/proxy-link-parser.sh
    log "PROXY_LINK accept: ${PROXY_LINK:0:9}*****"
  else
    warn "PROXY_LINK set by default on: WARP"
  fi

  case "${WARP_OVER_PROXY:-}" in
    true|false)
      log "WARP_OVER_PROXY accept: ${WARP_OVER_PROXY}"
    ;;
    *)
      warn "WARP_OVER_PROXY set by default on: false"
      WARP_OVER_PROXY="false"
    ;;
  esac

  case "${WARP_OVER_DIRECT:-}" in
    true|false)
      log "WARP_OVER_DIRECT accept: ${WARP_OVER_DIRECT}"
    ;;
    *)
      warn "WARP_OVER_DIRECT set by default on: false"
      WARP_OVER_DIRECT="false"
    ;;
  esac

  if [[ -n "${ROUTE_CIDR:-}" ]]; then
    if is_ip_cidr_list "$ROUTE_CIDR"; then
      log "ROUTE_CIDR accept: $ROUTE_CIDR"
    else
      exiterr "ROUTE_CIDR must be a valid ipv4/ipv6 CIDR list"
    fi
  else
    warn "ROUTE_CIDR not set, using all WG interfaces routes by default"
  fi

  case "${ROUTE_FINAL:-}" in
    proxy|direct)
      log "ROUTE_FINAL accept: ${ROUTE_FINAL}"
      ROUTE_BYPASS=$([[ "$ROUTE_FINAL" == "proxy" ]] && echo "direct" || echo "proxy")
    ;;
    *)
      warn "ROUTE_FINAL set by default on: direct"
      ROUTE_FINAL="direct"
      ROUTE_BYPASS="proxy"
    ;;
  esac

  if [[ -n "${BYPASS_GEOSITE:-}" ]]; then
    BYPASS_GEOSITE="${BYPASS_GEOSITE,,}"
    if validate_geosite_name_rules "$BYPASS_GEOSITE"; then
      log "BYPASS_GEOSITE accept: ${BYPASS_GEOSITE:0:9}....."
    else
      exiterr "BYPASS_GEOSITE must be a valid"
    fi
  fi

  if [[ -n "${BYPASS_GEOIP:-}" ]]; then
    BYPASS_GEOIP="${BYPASS_GEOIP,,}"
    if validate_geoip_name_rules "$BYPASS_GEOIP"; then
      log "BYPASS_GEOIP accept: ${BYPASS_GEOIP:0:9}....."
    else
      exiterr "BYPASS_GEOIP must be a valid"
    fi
  fi

  if [[ -n "${PASS_SITES:-}" ]]; then
    PASS_SITES=$(convert_domains "$PASS_SITES")
  fi

  echo "------------------------------------------------------------"
}

ensure_installation(){
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

set_envvars(){
  if [[ ! -s "${WGD_DATA_CONFIG}" ]]; then
    log "Config file is empty. Creating template."
    {
      echo "[Peers]"
      echo "peer_global_dns = 1.1.1.1"
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

  check_and_update_var "remote_endpoint" "${WGD_HOST}"
  check_and_update_var "app_port" "${WGD_PORT}"
  check_and_update_var "log_level" "${WGD_LOG_LEVEL}"
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

start_sing_box(){
  get_geo_list_data() {
    local geosite_list="$1"
    local geoip_list="$2"
    local prefix_name="$3"
    local geo_list=()
    local url_list=()
    add_items() {
      local prefix="$1"
      local values="$2"
      local item
      local IFS=',';
      read -ra tmp <<< "$values"
      for item in "${tmp[@]}"; do
        item="${item// /}"
        if [[ "$item" =~ ^https?:// ]]; then
          url_list+=("$item")
        else
          geo_list+=("${prefix}${item}")
        fi
      done
    }
    [[ -n "$geosite_list" ]] && add_items "geosite-" "$geosite_list"
    [[ -n "$geoip_list" ]] && add_items "geoip-" "$geoip_list"
    declare -A seen
    local unique_geo=()
    for item in "${geo_list[@]}"; do
      if [[ -n "$item" && -z "${seen[$item]}" ]]; then
        unique_geo+=("$item")
        seen["$item"]=1
      fi
    done
    unset seen
    declare -A seen
    local unique_url=()
    for item in "${url_list[@]}"; do
      if [[ -n "$item" && -z "${seen[$item]}" ]]; then
        unique_url+=("$item")
        seen["$item"]=1
      fi
    done
    local IFS=','; GEO_NAMES_LIST="${unique_geo[*]}"
    local final_names_list names_list=()
    for i in "${!unique_url[@]}"; do
      names_list+=("${prefix_name}$((i + 1))")
    done
    final_names_list="$(IFS=','; echo "${names_list[*]}")"
    if [[ -n "$GEO_NAMES_LIST" && -n "$final_names_list" ]]; then
      GEO_NAMES_LIST="${GEO_NAMES_LIST},${final_names_list}"
    elif [[ -z "$GEO_NAMES_LIST" && -n "$final_names_list" ]]; then
      GEO_NAMES_LIST="${final_names_list}"
    fi
    local GEO_ONLY_URL_LIST
    GEO_ONLY_URL_LIST="${unique_url[*]}"
    local names=()
    local urls=()
    local result=()
    IFS=','; read -ra names <<< "$GEO_NAMES_LIST"
    IFS=','; read -ra urls <<< "$GEO_ONLY_URL_LIST"
    local url_index=0
    for name in "${names[@]}"; do
      if [[ "$name" =~ ^(geosite|geoip)- ]]; then
        continue
      fi
      if [[ -n "${urls[$url_index]}" ]]; then
        result+=("${name}@${urls[$url_index]}")
        ((url_index++))
      fi
    done
    IFS='|'; GEO_URL_LIST="${result[*]}"
  }

  local geo_block_list geo_block_list_format block_sites geo_block_url_list
  [ -n "$BLOCK_SITES" ] && block_sites="\"${BLOCK_SITES//,/\",\"}\""
  if [[ -n "$BLOCK_GEOSITE" || -n "$BLOCK_GEOIP" ]]; then
    get_geo_list_data "$BLOCK_GEOSITE" "$BLOCK_GEOIP" "block-"
    geo_block_list="${GEO_NAMES_LIST}"
    geo_block_list_format="\"${geo_block_list//,/\",\"}\""
    geo_block_url_list="${GEO_URL_LIST}"
  fi

  local route_cidr pass_sites geo_bypass_list geo_bypass_list_format geo_bypass_url_list
  [ -n "$ROUTE_CIDR" ] && route_cidr="\"${ROUTE_CIDR//,/\",\"}\""
  [ -n "$PASS_SITES" ] && pass_sites="\"${PASS_SITES//,/\",\"}\""
  if [[ -n "$BYPASS_GEOSITE" || -n "$BYPASS_GEOIP" ]]; then
    get_geo_list_data "$BYPASS_GEOSITE" "$BYPASS_GEOIP" "bypass-"
    geo_bypass_list="${GEO_NAMES_LIST}"
    geo_bypass_list_format="\"${geo_bypass_list//,/\",\"}\""
    geo_bypass_url_list="${GEO_URL_LIST}"
  fi

  gen_dns_servers(){
    local direct_path proxy_path
    local output=()
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
        output+=('{"tag":"dns-proxy","type":"local","detour":"proxy"}')
      else
        [[ "$DNS_PROXY_TYPE" == "https" ]] && proxy_path="\"path\":\"${DNS_PROXY_PATH}\","
        output+=("{\"tag\":\"dns-proxy\",\"type\":\"${DNS_PROXY_TYPE}\",
          \"server\":\"${DNS_PROXY_SERVER}\",\"server_port\":${DNS_PROXY_SERVER_PORT},
          ${proxy_path}\"domain_resolver\":\"dns-domain-resolver\",\"detour\":\"proxy\"
        }")
      fi
    fi
    [ -f "$HOSTS_FILE" ] && output+=("{\"tag\":\"dns-hosts\",\"type\":\"hosts\",\"path\":\"${HOSTS_FILE}\"}")
    output+=("{\"tag\":\"dns-domain-resolver\",\"type\":\"local\"}")
    IFS=','; echo "${output[*]}"
  }

  gen_dns_rules(){
    local output=()
    [[ -f "$HOSTS_FILE" ]] && output+=('{"ip_accept_any":true,"server":"dns-hosts"}')
    [[ "$ENABLE_ADGUARD" == "true" ]] && output+=('{"rule_set":["adguard"],"action":"predefined"}')
    [[ -n "$block_sites" ]] && output+=("{\"domain_suffix\":[${block_sites}],\"action\":\"predefined\"}")
    [[ -n "$geo_block_list" ]] && output+=("{\"rule_set\":[${geo_block_list_format}],\"action\":\"predefined\"}")
    [[ -n "$route_cidr" ]] && output+=("{\"source_ip_cidr\":[${route_cidr}],\"invert\":true,\"server\":\"dns-direct\"}")
    if [[ -n "$geo_bypass_list" ]]; then
      if [[ "$ROUTE_BYPASS" == "direct" ]] || [[ -f "$WARP_ENDPOINT" || -n "$PROXY_LINK" ]]; then
        local rewrite_ttl
        local rule_set="{\"rule_set\":[${geo_bypass_list_format}],\"server\":\"dns-${ROUTE_BYPASS}\""
        [[ "$ROUTE_BYPASS" == "proxy" ]] && rewrite_ttl=",\"rewrite_ttl\":${DNS_PROXY_TTL}"
        [[ -n "$pass_sites" ]] && output+=("{\"domain_suffix\":[${pass_sites}],\"server\":\"dns-${ROUTE_FINAL}\"}")
        output+=("${rule_set}${rewrite_ttl}}")
      fi
    fi
    IFS=','; echo "${output[*]}"
  }

  gen_endpoints(){
    local output=()
    if [[ -f "$WARP_ENDPOINT" && -z "$PROXY_LINK" ]]; then
      output+=("$(cat "$WARP_ENDPOINT")")
    elif [[ -f "${WARP_ENDPOINT}.over_proxy" && "$WARP_OVER_PROXY" == "true" ]]; then
      output+=("$(cat "${WARP_ENDPOINT}.over_proxy")")
    fi
    if [[ -f "${WARP_ENDPOINT}.over_direct" && "$WARP_OVER_DIRECT" == "true" ]]; then
      output+=("$(cat "${WARP_ENDPOINT}.over_direct")")
    fi
    if [[ -n "$PROXY_ENDPOINT" ]]; then
      output+=("$PROXY_ENDPOINT")
    fi
    IFS=','; echo "${output[*]}"
  }

  gen_outbounds(){
    local output=()
    if [[ "$WARP_OVER_DIRECT" == "false" || ! -f "${WARP_ENDPOINT}.over_direct" ]]; then
      output+=('{"tag":"direct","type":"direct"}')
    fi
    if [[ -z "$PROXY_ENDPOINT" && -n "$PROXY_LINK" ]]; then
      output+=("$PROXY_OUTBOUND")
    fi
    local IFS=','
    echo "${output[*]}"
  }

  gen_route_rules(){
    local output=()
    output+=('
    {"action":"sniff"},
    {"type":"logical","mode":"or","rules":[{"protocol":"dns"},{"port":53}],"action":"hijack-dns"},
    {"ip_is_private":true,"outbound":"direct"}
    ')
    [[ "$ENABLE_ADGUARD" == "true" ]] && output+=('{"rule_set":["adguard"],"action":"reject"}')
    [[ -n "$block_sites" ]] && output+=("{\"domain_suffix\":[${block_sites}],\"action\":\"reject\"}")
    [[ -n "$geo_block_list" ]] && output+=("{\"rule_set\":[${geo_block_list_format}],\"action\":\"reject\"}")
    [[ -n "$route_cidr" ]] && output+=("{\"source_ip_cidr\":[${route_cidr}],\"invert\":true,\"outbound\":\"direct\"}")
    if [[ "$ROUTE_BYPASS" == "direct" ]] || [[ -f "$WARP_ENDPOINT" || -n "$PROXY_LINK" ]]; then
      [[ -n "$geo_bypass_list" && -n "$pass_sites" ]] && \
      output+=("{\"domain_suffix\":[${pass_sites}],\"outbound\":\"${ROUTE_FINAL}\"}")
      [[ -n "$geo_bypass_list" ]] && \
      output+=("{\"rule_set\":[${geo_bypass_list_format}],\"outbound\":\"${ROUTE_BYPASS}\"}")
    fi
    local IFS=','
    echo "${output[*]}"
  }

  gen_route_rule_set() {
    local geo_rules=()
    local geo_url_rules=()
    local geo_list geo_url_list rules rule base_url
    local output=()
    local download_detour="proxy"
    [[ ! -f "$WARP_ENDPOINT" && -z "$PROXY_LINK" ]] && download_detour="direct"
    if [[ -n "$geo_block_list" || -n "$geo_bypass_list" ]]; then
      geo_rules+=("$geo_block_list" "$geo_bypass_list")
      local IFS=','; geo_list="${geo_rules[*]}"
      declare -A seen
      local unique_geo=()
      IFS=','; read -ra entries <<< "$geo_list"
      for item in "${entries[@]}"; do
        if [[ -n "$item" && -z "${seen[$item]}" ]]; then
          unique_geo+=("$item")
          seen["$item"]=1
        fi
      done
      for rule in "${unique_geo[@]}"; do
        [[ -z "$rule" || ! "$rule" =~ ^(geosite|geoip)- ]] && continue
        base_url="https://raw.githubusercontent.com/SagerNet/sing-${rule%%-*}/rule-set/${rule}.srs"
        output+=("{\"tag\":\"${rule}\",\"type\":\"remote\",\"format\":\"binary\",\"url\":\"${base_url}\",\"download_detour\":\"$download_detour\",\"update_interval\":\"1d\"}")
      done
    fi
    if [[ -n "$geo_block_url_list" || -n "$geo_bypass_url_list" ]]; then
      geo_url_rules+=("$geo_block_url_list" "$geo_bypass_url_list")
      IFS='|'; geo_url_list="${geo_url_rules[*]}"
      IFS='|'; read -ra entries <<< "$geo_url_list"
      for rule in "${entries[@]}"; do
        [[ -z "$rule" || ! "$rule" =~ ^block-|^bypass- ]] && continue
        base_url="${rule#*@}"
        rule="${rule%@*}"
        output+=("{\"tag\":\"${rule}\",\"type\":\"remote\",\"format\":\"binary\",\"url\":\"${base_url}\",\"download_detour\":\"$download_detour\",\"update_interval\":\"1d\"}")
      done
    fi
    if [[ "$ENABLE_ADGUARD" == "true" ]]; then
      base_url="http://raw.githubusercontent.com/jinndi/adguard-filter-list-srs/main/adguard-filter-list.srs"
      output+=("{\"tag\":\"adguard\",\"type\":\"remote\",\"format\":\"binary\",\"url\":\"${base_url}\",\"download_detour\":\"$download_detour\",\"update_interval\":\"1d\"}")
    fi
    IFS=','; echo "${output[*]}"
  }

  log "sing-box creating config"

cat << EOF > "$SINGBOX_CONFIG"
{
  "log": {
    "disabled": false, "level": "$LOG_LEVEL", "timestamp": true
  },
  "dns": {
    "servers": [$(gen_dns_servers)],
    "rules": [$(gen_dns_rules)],
    "final": "dns-${ROUTE_FINAL}",
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
  "endpoints": [$(gen_endpoints)],
  "outbounds": [$(gen_outbounds)],
  "route": {
    "rules": [$(gen_route_rules)],
    "rule_set": [$(gen_route_rule_set)],
    "final": "${ROUTE_FINAL}",
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

  sing-box run -c "$SINGBOX_CONFIG" \
    --disable-color > "$SINGBOX_ERR_LOG" 2>&1 &
  SINGBOX_PID=$!
}

start_core(){
  log "Start WGDashboard"

  gunicorn --config ./gunicorn.conf.py &
  GUNICORN_PID=$!

  log "Waiting for Gunicorn PID file..."
  local checkPIDExist=0
  local timeout=40
  local waited=0

  while [ $checkPIDExist -eq 0 ]; do
    if [[ -f "$WGD_PID" ]]; then
      checkPIDExist=1
      log "Gunicorn PID file found, WGDashboard starting"
    else
      sleep 1
      waited=$((waited+1))
      if [ $waited -ge $timeout ]; then
        exiterr "Gunicorn PID file not found after $timeout seconds, exiting"
      fi
    fi
  done
  log "WGDashboard Gunicorn started successfully (PID: $GUNICORN_PID)"

  log "Apply iptables forwards"
  . /scripts/auto-iptables-forward.sh
}

stop_core() {
  log "Stopping services..."

  if [[ -n "$GUNICORN_PID" ]] && kill -0 "$GUNICORN_PID" 2>/dev/null; then
    log "Stopping Gunicorn..."
    kill -TERM "$GUNICORN_PID"
    wait "$GUNICORN_PID"
  fi

  if [[ -n "$SINGBOX_PID" ]] && kill -0 "$SINGBOX_PID" 2>/dev/null; then
    log "Stopping Sing-box..."
    kill -TERM "$SINGBOX_PID"
    wait "$SINGBOX_PID"
  fi

  log "All services stopped"
}
trap 'stop_core' SIGTERM SIGINT

ensure_blocking(){
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

echo -e "\n-------------------- STARTING SING-BOX ---------------------"
start_sing_box

echo -e "\n---------------------- STARTING CORE -----------------------"
start_core

echo -e "\n------------------------ SHOW LOGS -------------------------"
ensure_blocking
