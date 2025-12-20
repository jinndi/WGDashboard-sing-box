#!/usr/bin/env bash
# The output is the environment variable PROXY_OUTBOUND

tuic_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN CREDS HOSTPORT QUERY
  local TUIC_UUID TUIC_PSK TUIC_HOST TUIC_PORT
  local TUIC_SNI TUIC_ALPN TUIC_CONGESTION_CONTROL TUIC_UDP_RELAY_MODE

  PROXY_LINK="$1"
  TAG="$2"
  # Remove the tuic:// scheme
  STRIPPED="${PROXY_LINK#tuic://}"
  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  MAIN="${MAIN%%/*}"
  QUERY="${STRIPPED#*\?}"
  QUERY="${QUERY%%#*}"

  # Split credentials (CREDS) and host:port
  CREDS="${MAIN%@*}"       # UUID:password
  HOSTPORT="${MAIN##*@}"   # host:port
  HOSTPORT="${HOSTPORT%%/*}"

  # Split UUID PSK HOST PORT
  TUIC_UUID="${CREDS%%:*}"
  TUIC_UUID="${TUIC_UUID,,}"
  TUIC_PSK="$(urldecode "${CREDS#*:}")"
  TUIC_HOST="${HOSTPORT%%:*}"
  TUIC_PORT="${HOSTPORT##*:}"

  # Debug
  # echo "TUIC_UUID=$TUIC_UUID"
  # echo "TUIC_PSK=$TUIC_PSK"
  # echo "TUIC_HOST=$TUIC_HOST"
  # echo "TUIC_PORT=$TUIC_PORT"

  # Check TUIC_UUID (must be UUID v4)
  if [[ -z "$TUIC_UUID" || \
    ! "$TUIC_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]
  then
    exiterr "TUIC UUID is empty or not a valid UUIDv4"
  fi

  # Check TUIC_PSK
  if [[ -z "$TUIC_PSK" ]]; then
    exiterr "TUIC PASSWORD is empty"
  fi

  # Checking TUIC_HOST (domain or IP)
  if ! is_domain "$TUIC_HOST" && ! is_ipv4 "$TUIC_HOST"; then
    exiterr "TROJAN HOST must be a valid domain or IPv4 address"
  fi

  # Check TUIC_PORT (must be a number from 1 to 65535)
  if ! is_port "$TUIC_PORT"; then
    exiterr "TROJAN PORT is empty or not a valid port (1-65535)"
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
        [[ "$val" != "tls" ]] && exiterr "TUIC SECURITY must be 'tls'"
      ;;
      SNI)
        if ! is_domain "$val"; then
          exiterr "TUIC SNI must be a valid domain"
        fi
      ;;
      INSECURE)
        [[ "$val" != "0" ]] && exiterr "TUIC INSECURE is not: 0"
      ;;
      ALPN)
        [[ "$val" != "h3" ]] && \
          exiterr "TUIC ALPN value '$val' is not allowed. Allowed: h3"
      ;;
      CONGESTION_CONTROL)
        [[ ! "$val" =~ ^(cubic|new_reno|bbr)$ ]] && \
          exiterr "TUIC CONGESTION_CONTROL is not: cubic, new_reno or bbr"
      ;;
      UDP_RELAY_MODE)
        [[ ! "$val" =~ ^(native|quic)$ ]] && \
          exiterr "TUIC UDP_RELAY_MODE is not: native or quic"
      ;;
      *)
        continue
      ;;
    esac
    # Declare QUERY variable
    declare "TUIC_${key}=${val}"
    # Debug
    # echo "TUIC_${key}=${val}"
  done

  # Export PROXY_OUTBOUND
  [[ -z "$TUIC_SNI" ]] && is_domain "$TUIC_HOST" && TUIC_SNI="$TUIC_HOST"
  [[ -z "$TUIC_SNI" ]] && exiterr "TUIC PROXY_LINK is incorrect: empty SNI"
  [[ -z "$TUIC_CONGESTION_CONTROL" ]] && TUIC_CONGESTION_CONTROL="bbr"
  [[ -z "$TUIC_UDP_RELAY_MODE" ]] && TUIC_UDP_RELAY_MODE="native"
  [[ -z "$TUIC_ALPN" ]] && TUIC_ALPN="h3"

  # Export PROXY_OUTBOUND
  export PROXY_OUTBOUND="{\"tag\":\"${TAG}\",\"type\":\"tuic\",
  \"server\":\"${TUIC_HOST}\",\"server_port\":${TUIC_PORT},
  \"uuid\":\"${TUIC_UUID}\",\"password\":\"${TUIC_PSK}\",
  \"congestion_control\":\"${TUIC_CONGESTION_CONTROL}\",
  \"udp_relay_mode\":\"${TUIC_UDP_RELAY_MODE}\",\"heartbeat\":\"10s\",
  \"tls\":{\"enabled\":true,\"insecure\":false,\"server_name\":\"${TUIC_SNI}\",
  \"alpn\":[\"${TUIC_ALPN}\"]}}"
}

tuic_parse_link "$1" "$2"
