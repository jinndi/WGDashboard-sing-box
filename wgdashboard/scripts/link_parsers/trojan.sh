#!/usr/bin/env bash
# The output is the environment variable PROXY_OUTBOUND

trojan_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN QUERY HOSTPORT
  local TROJAN_PSK TROJAN_HOST TROJAN_PORT
  local TROJAN_TYPE TROJAN_SECURITY TROJAN_SNI TROJAN_ALPN TROJAN_FP
  local TROJAN_MULTIPLEX_ENABLE="false"
  local TROJAN_MULTIPLEX_PROTO="h2mux"

  PROXY_LINK="$1"
  TAG="$2"
  # Remove the trojan:// scheme
  STRIPPED="${PROXY_LINK#trojan://}"
  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  MAIN="${MAIN%%/*}"
  QUERY="${STRIPPED#*\?}"
  QUERY="${QUERY%%#*}"

  # --- MAIN (psk@host:port) ---
  TROJAN_PSK="$(urldecode "${MAIN%@*}")"
  HOSTPORT="${MAIN#*@}"
  TROJAN_HOST="${HOSTPORT%%:*}"
  TROJAN_PORT="${HOSTPORT##*:}"

  # Debug
  # echo "TROJAN_PSK=$TROJAN_PSK"
  # echo "TROJAN_HOST=$TROJAN_HOST"
  # echo "TROJAN_PORT=$TROJAN_PORT"

  # Check TROJAN_PSK
  if [[ -z "$TROJAN_PSK" ]]; then
    exiterr "TROJAN PASSWORD is empty"
  fi

  # Checking TROJAN_HOST (domain or IP)
  if ! is_domain "$TROJAN_HOST" && ! is_ipv4 "$TROJAN_HOST"; then
    exiterr "TROJAN HOST must be a valid domain or IPv4 address"
  fi

  # Check TROJAN_PORT (must be a number from 1 to 65535)
  if ! is_port "$TROJAN_PORT"; then
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
        [[ "$val" != "tls" ]] && exiterr "TROJAN SECURITY must be 'tls'"
      ;;
      TYPE)
        [[ "$val" != "tcp" ]] && exiterr "TROJAN TYPE is not 'tcp'"
      ;;
      ENCRYPTION)
        [[ "$val" != "none" ]] && exiterr "TROJAN ENCRYPTION is not 'none'"
      ;;
      SNI) # Check for domain name (sub.domain.tld)
        if ! is_domain "$val"; then
          exiterr "TROJAN SNI must be a valid domain"
        fi
      ;;
      FP) # Fingerprint check
        if [[ ! "$val" =~ ^(chrome|firefox|edge|safari|360|qq|ios|android|random|randomized)$ ]]; then
          warn "TROJAN fingerprint set by default on: chrome"
          val=chrome
        fi
      ;;
      ALPN)
        IFS=',' read -ra ALPN_VALUES <<< "$val"
        for v in "${ALPN_VALUES[@]}"; do
          case "$v" in
            "http/1.1"|"h2"|"h3")
              ;;
            *)
              exiterr "TROJAN ALPN value '$val' is not allowed. Allowed: http/1.1, h2, h3"
            ;;
          esac
        done
      ;;
      MULTIPLEX)
        [[ ! "$val" =~ ^(smux|yamux|h2mux)$ ]] && exiterr "TROJAN MULTIPLEX is not: smux, yamux or h2mux"
        TROJAN_MULTIPLEX_ENABLE="true"
        TROJAN_MULTIPLEX_PROTO="$val"
      ;;
      *)
        continue
      ;;
    esac
    # Declare QUERY variable
    declare "TROJAN_${key}=${val}"
    # Debug
    # echo "TROJAN_${key}=${val}"
  done

  case "$TROJAN_SECURITY" in
    tls)
      [[ -z "$TROJAN_SNI" ]] && is_domain "$TROJAN_HOST" && TROJAN_SNI="$TROJAN_HOST"
      [[ -z "$TROJAN_TYPE" || -z "$TROJAN_SNI" ||  -z "$TROJAN_FP" ]] && \
        exiterr "TROJAN TLS PROXY_LINK is incorrect: empty TYPE or SNI or FP"
    ;;
    *)
      exiterr "TROJAN PROXY_LINK is incorrect: not support SECURITY=$TROJAN_SECURITY"
    ;;
  esac

  [[ -n "$TROJAN_ALPN" ]] && TROJAN_ALPN="\"alpn\":[\"${TROJAN_ALPN//,/\",\"}\"],"

  # Export PROXY_OUTBOUND
  export PROXY_OUTBOUND="{\"tag\":\"${TAG}\",\"type\":\"trojan\",\"server\":\"${TROJAN_HOST}\",
  \"server_port\":${TROJAN_PORT},\"password\":\"${TROJAN_PSK}\",
  \"network\":\"$TROJAN_TYPE\",\"tcp_fast_open\":true,\"tcp_multi_path\":true,
  \"tls\":{\"enabled\":true,\"insecure\":false,\"server_name\":\"${TROJAN_SNI}\",${TROJAN_ALPN}
  \"utls\":{\"enabled\":true,\"fingerprint\":\"${TROJAN_FP}\"}},
  \"multiplex\":{\"enabled\":${TROJAN_MULTIPLEX_ENABLE},\"protocol\":\"${TROJAN_MULTIPLEX_PROTO}\",
  \"padding\":false,\"brutal\":{\"enabled\":false}}}"
}

trojan_parse_link "$1" "$2"
