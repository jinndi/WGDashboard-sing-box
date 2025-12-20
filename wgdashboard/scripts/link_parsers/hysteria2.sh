#!/usr/bin/env bash
# The output is the environment variable PROXY_OUTBOUND

hysteria2_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN QUERY HOSTPORT
  local HY2_PSK HY2_HOST HY2_PORT
  local HY2_SNI HY2_ALPN

  PROXY_LINK="$1"
  TAG="$2"
  # Remove the hy2:// scheme
  STRIPPED="${PROXY_LINK#hysteria2://}"
  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  MAIN="${MAIN%%/*}"
  QUERY="${STRIPPED#*\?}"
  QUERY="${QUERY%%#*}"

  # --- MAIN (psk@host:port) ---
  HY2_PSK="$(urldecode "${MAIN%@*}")"
  HOSTPORT="${MAIN#*@}"
  HY2_HOST="${HOSTPORT%%:*}"
  HY2_PORT="${HOSTPORT##*:}"

  # Debug
  # echo "HY2_PSK=$HY2_PSK"
  # echo "HY2_HOST=$HY2_HOST"
  # echo "HY2_PORT=$HY2_PORT"

  # Check HY2_PSK
  if [[ -z "$HY2_PSK" ]]; then
    exiterr "Hysteria2 PASSWORD is empty"
  fi

  # Checking HY2_HOST (domain or IP)
  if ! is_domain "$HY2_HOST" && ! is_ipv4 "$HY2_HOST"; then
    exiterr "Hysteria2 HOST must be a valid domain or IPv4 address"
  fi

  # Check HY2_PORT (must be a number from 1 to 65535)
  if ! is_port "$HY2_PORT"; then
    exiterr "Hysteria2 PORT is empty or not a valid port (1-65535)"
  fi

  # --- QUERY (key=value) ---
  IFS='&' read -ra PAIRS <<< "$QUERY"
  for kv in "${PAIRS[@]}"; do
    key="${kv%%=*}"
    key="${key^^}"
    val="${kv#*=}"
    val="${val,,}"
    val="$(urldecode "$val")"
    case "$key" in
      SECURITY)
        [[ "$val" != "tls" ]] && exiterr "Hysteria2 SECURITY must be 'tls'"
      ;;
      SNI)
        if ! is_domain "$val"; then
          exiterr "Hysteria2 SNI must be a valid domain"
        fi
      ;;
      ALPN)
        [[ "$val" != "h3" ]] && exiterr "Hysteria2 ALPN value '$val' is not allowed. Allowed: h3"
      ;;
      INSECURE)
        [[ "$val" != "0" ]] && exiterr "Hysteria2 INSECURE is not: 0"
      ;;
      *)
        continue
      ;;
    esac
    # Declare QUERY variable
    declare "HY2_${key}=${val}"
    # Debug
    # echo "HY2_${key}=${val}"
  done

  [[ -z "$HY2_SNI" ]] && is_domain "$HY2_HOST" && HY2_SNI="$HY2_HOST"
  [[ -z "$HY2_SNI" ]] && exiterr "Hysteria2 PROXY_LINK is incorrect: empty SNI"
  [[ -z "$HY2_ALPN" ]] && HY2_ALPN="h3"

  # Export PROXY_OUTBOUND
  export PROXY_OUTBOUND="{\"tag\":\"${TAG}\",\"type\":\"hysteria2\",
  \"server\":\"${HY2_HOST}\",\"server_port\":${HY2_PORT},\"password\":\"${HY2_PSK}\",
  \"tls\":{\"enabled\":true,\"insecure\":false,\"server_name\":\"${HY2_SNI}\",
  \"alpn\":[\"${HY2_ALPN}\"]}}"
}

hysteria2_parse_link "$1" "$2"
