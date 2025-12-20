#!/usr/bin/env bash
# The output is the environment variable PROXY_OUTBOUND

ss2022_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN QUERY
  local CREDS HOSTPORT
  local SS_METHOD SS_PASSWORD SS_HOST SS_PORT
  local MULTIPLEX_ENABLE="false"
  local MULTIPLEX_PROTO="h2mux"

  PROXY_LINK="$1"
  TAG="$2"

  # Remove ss:// prefix
  STRIPPED="${PROXY_LINK#ss://}"

  # Strip fragment (#...)
  STRIPPED="${STRIPPED%%#*}"

  # Split query if exists
  if [[ "$STRIPPED" == *\?* ]]; then
    MAIN="${STRIPPED%%\?*}"
    QUERY="${STRIPPED#*\?}"
  else
    MAIN="$STRIPPED"
    QUERY=""
  fi

  # Split credentials and host:port
  CREDS="${MAIN%@*}"       # method:password (possibly Base64)
  HOSTPORT="${MAIN##*@}"   # host:port
  HOSTPORT="${HOSTPORT%%/*}"

  # Decode Base64 CREDS
  DECODED=$(printf '%s' "$CREDS" \
  | tr '_-' '/+' \
  | openssl base64 -d -A 2>/dev/null) \
  || exiterr "Invalid Base64 in Shadowsocks credentials"

  [[ "$DECODED" != *:* ]] && \
    exiterr "Invalid decoded Shadowsocks credentials format"

  CREDS="$DECODED"

  SS_METHOD="${CREDS%%:*}"
  SS_METHOD="${SS_METHOD,,}"
  SS_PASSWORD="${CREDS#"$SS_METHOD:"}"
  SS_HOST="${HOSTPORT%%:*}"
  SS_PORT="${HOSTPORT##*:}"

  # Debug
  # echo "SS_METHOD=$SS_METHOD"
  # echo "SS_PASSWORD=$SS_PASSWORD"
  # echo "SS_HOST=$SS_HOST"
  # echo "SS_PORT=$SS_PORT"

  # Checking SS_METHOD SS_PASSWORD
  [[ -z "$SS_METHOD" ]] && exiterr "Shadowsocks-2022 METHOD is empty"
  [[ -z "$SS_PASSWORD" ]] && exiterr "Shadowsocks-2022 PASSWORD is empty"

  case "$SS_METHOD" in
    2022-blake3-aes-128-gcm)
      #
    ;;
    2022-blake3-aes-256-gcm)
      #
    ;;
    2022-blake3-chacha20-poly1305)
      #
    ;;
    *)
      exiterr "Shadowsocks-2022 METHOD must be: blake3-aes-128-gcm, blake3-aes-256-gcm or blake3-chacha20-poly1305"
    ;;
  esac

  # Checking SS_HOST (domain or IP)
  if ! is_domain "$SS_HOST" && ! is_ipv4 "$SS_HOST"; then
    exiterr "Shadowsocks-2022 HOST must be a valid domain or IPv4 address"
  fi

  # Check SS_PORT (must be a number from 1 to 65535)
  if ! is_port "$SS_PORT"; then
    exiterr "Shadowsocks-2022 PORT is empty or not a valid port (1-65535)"
  fi

  # Parse optional query
  if [[ -n "$QUERY" ]]; then
    IFS='&' read -ra PAIRS <<< "$QUERY"
    for kv in "${PAIRS[@]}"; do
      key="${kv%%=*}"
      key="${key^^}"
      val="${kv#*=}"
      val="${val,,}"
      case "$key" in
        TYPE)
          [[ "$val" != "tcp" ]] && exiterr "Shadowsocks-2022 TYPE is not 'tcp'"
        ;;
        MULTIPLEX)
          [[ ! "$val" =~ ^(smux|yamux|h2mux)$ ]] && \
            exiterr "Shadowsocks-2022 multiplex is not 'smux', 'yamux' or 'h2mux'"
          MULTIPLEX_ENABLE="true"
          MULTIPLEX_PROTO="$val"
        ;;
      esac
    done
  fi

  # Export PROXY_OUTBOUND
  export PROXY_OUTBOUND="{\"tag\":\"${TAG}\",\"type\":\"shadowsocks\",
  \"server\":\"${SS_HOST}\",\"server_port\":${SS_PORT},
  \"method\":\"${SS_METHOD}\",\"password\":\"${SS_PASSWORD}\",
  \"tcp_fast_open\":true,\"tcp_multi_path\":true,
  \"multiplex\":{\"enabled\":${MULTIPLEX_ENABLE},\"protocol\":\"${MULTIPLEX_PROTO}\",
  \"padding\":false,\"brutal\":{\"enabled\":false}}}"
}

ss2022_parse_link "$1" "$2"
