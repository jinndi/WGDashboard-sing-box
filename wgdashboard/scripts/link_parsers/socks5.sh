#!/usr/bin/env bash
# The output is the environment variable PROXY_OUTBOUND

socks5_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN QUERY CREDS HOSTPORT
  local SOCKS_USER SOCKS_PASS SOCKS_HOST SOCKS_PORT
  local SOCKS_UOT="false"

  PROXY_LINK="$1"
  TAG="$2"

  # Remove prefix (socks5://)
  STRIPPED="${PROXY_LINK#socks5://}"

  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  MAIN="${MAIN%%/*}"
  QUERY="${STRIPPED#*\?}"
  QUERY="${QUERY%%#*}"

  # Split credentials and host:port
  if [[ "$STRIPPED" == *"@"* ]]; then
    CREDS="${MAIN%@*}"       # username:password
    SOCKS_USER="$(urldecode "${CREDS%%:*}")"
    SOCKS_PASS="$(urldecode "${CREDS#*:}")"
    HOSTPORT="${MAIN##*@}"   # host:port
  else
    HOSTPORT="$MAIN"
  fi

  # Split host and port
  SOCKS_HOST="${HOSTPORT%%:*}"
  SOCKS_PORT="${HOSTPORT##*:}"

  # Debug
  # echo "SOCKS_USER=$SOCKS_USER"
  # echo "SOCKS_PASS=$SOCKS_PASS"
  # echo "SOCKS_HOST=$SOCKS_HOST"
  # echo "SOCKS_PORT=$SOCKS_PORT"

  # Validation
  if [[ -z "$SOCKS_HOST" ]]; then
    exiterr "SOCKS5 HOST is empty"
  fi
  if ! is_port "$SOCKS_PORT"; then
    exiterr "SOCKS5 PORT is empty or not a valid port (1-65535)"
  fi

  # Parse optional query
  if [[ -n "$QUERY" ]]; then
    IFS='&' read -ra PAIRS <<< "$QUERY"
    for kv in "${PAIRS[@]}"; do
      key="${kv%%=*}"
      key="${key^^}"
      val="${kv#*=}"
      val="${val,,}"
      val="$(urldecode "${val}")"
      case "$key" in
        UOT)
          if [[ "$val" != "false" && "$val" != "true" ]]; then
            warn "SOCKS5 UDP over TCP (UoT) is not 'true' or 'false', set to 'false' by default"
            SOCKS_UOT="false"
          else
            SOCKS_UOT="$val"
          fi
        ;;
      esac
      # Debug
      # echo "$key=$val"
    done
  fi

  # Build and export PROXY_OUTBOUND
  PROXY_OUTBOUND="{\"tag\":\"${TAG}\",\"type\":\"socks\",\
  \"server\":\"${SOCKS_HOST}\",\"server_port\":${SOCKS_PORT},\
  \"version\":\"5\",\"udp_over_tcp\":${SOCKS_UOT}"
  if [[ -n "$SOCKS_USER" || -n "$SOCKS_PASS" ]]; then
    PROXY_OUTBOUND+=",\"username\":\"${SOCKS_USER}\",\"password\":\"${SOCKS_PASS}\""
  fi
  PROXY_OUTBOUND+="}"
  export PROXY_OUTBOUND
}

socks5_parse_link "$1" "$2"
