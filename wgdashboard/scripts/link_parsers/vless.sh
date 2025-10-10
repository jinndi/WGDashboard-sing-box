#!/usr/bin/env bash
# The output is the environment variable PROXY_OUTBOUND

vless_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN QUERY HOSTPORT
  local VLESS_UUID VLESS_HOST VLESS_PORT
  local VLESS_SNI VLESS_PBK VLESS_SID VLESS_FP VLESS_ALPN
  local VLESS_TYPE VLESS_SECURITY VLESS_REALITY
  local VLESS_MULTIPLEX_ENABLE="false"
  local VLESS_MULTIPLEX_PROTO="h2mux"

  PROXY_LINK="$1"
  TAG="$2"
  # Remove the vless:// scheme
  STRIPPED="${PROXY_LINK#vless://}"
  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  MAIN="${MAIN%%/*}"
  QUERY="${STRIPPED#*\?}"
  QUERY="${QUERY%%#*}"

  # --- MAIN (uuid@host:port) ---
  VLESS_UUID="${MAIN%@*}"
  HOSTPORT="${MAIN#*@}"
  VLESS_HOST="${HOSTPORT%%:*}"
  VLESS_PORT="${HOSTPORT##*:}"

  # Debug
  # echo "VLESS_UUID=$VLESS_UUID"
  # echo "VLESS_HOST=$VLESS_HOST"
  # echo "VLESS_PORT=$VLESS_PORT"

  # Check VLESS_UUID (must be UUID v4)
  if [[ -z "$VLESS_UUID" || \
    ! "$VLESS_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]
  then
    exiterr "VLESS UUID is empty or not a valid UUIDv4"
  fi

  # Checking VLESS_HOST (domain or IP)
  if ! is_domain "$VLESS_HOST" && ! is_ipv4 "$VLESS_HOST"; then
    exiterr "VLESS HOST must be a valid domain or IPv4 address"
  fi

  # Check VLESS_PORT (must be a number from 1 to 65535)
  if ! is_port "$VLESS_PORT"; then
    exiterr "VLESS PORT is empty or not a valid port (1-65535)"
  fi

  # --- QUERY (key=value) ---
  IFS='&' read -ra PAIRS <<< "$QUERY"
  for kv in "${PAIRS[@]}"; do
    key="${kv%%=*}"
    key="${key^^}"
    val="${kv#*=}"
    val="$(urldecode "$val")"
    [[ "$key" != "PBK" ]] && val="${val,,}"
    case "$key" in
      SECURITY)
        [[ ! "$val" =~ ^(reality|tls)$ ]] && exiterr "VLESS SECURITY must be 'tls' or 'reality'"
      ;;
      TYPE)
        [[ "$val" != "tcp" ]] && exiterr "VLESS TYPE is not 'tcp'"
      ;;
      ENCRYPTION)
        [[ "$val" != "none" ]] && exiterr "VLESS ENCRYPTION is not 'none'"
      ;;
      PACKETENCODING)
        [[ "$val" != "xudp" ]] && exiterr "VLESS PACKETENCODING is not 'xudp'"
      ;;
      FLOW)
        [[ ! "$val" =~ ^(xtls-rprx-vision|none)$ ]] && \
        exiterr "VLESS FLOW is not 'xtls-rprx-vision', 'none' or no key"
        [[ "$val" == "none" ]] && val=""
      ;;
      SNI) # Check for domain name (sub.domain.tld)
        if ! is_domain "$val"; then
          exiterr "VLESS SNI must be a valid domain"
        fi
      ;;
      PBK) # Length of public key X25519 = 32 bytes → in Base64 URL-safe 43 characters.
        if [[ ! "$val" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
          exiterr "VLESS PBK must be a 43-character Base64 URL-safe public key"
        fi
      ;;
      SID) # May be empty, but if specified - only letters, numbers, hyphens or underscores
        if [[ ! "$val" =~ ^[0-9a-f]{0,16}$ ]]; then
          exiterr "VLESS SID must be 0–16 lowercase hex characters"
        fi
      ;;
      FP) # Fingerprint check
        if [[ ! "$val" =~ ^(chrome|firefox|edge|safari|360|qq|ios|android|random|randomized)$ ]]; then
          warn "VLESS fingerprint set by default on: chrome"
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
              exiterr "VLESS ALPN value '$val' is not allowed. Allowed: http/1.1, h2, h3"
            ;;
          esac
        done
      ;;
      MULTIPLEX)
        [[ ! "$val" =~ ^(smux|yamux|h2mux)$ ]] && exiterr "VLESS MULTIPLEX is not: smux, yamux or h2mux"
        VLESS_MULTIPLEX_ENABLE="true"
        VLESS_MULTIPLEX_PROTO="$val"
      ;;
      *)
        continue
      ;;
    esac
    # Declare QUERY variable
    declare "VLESS_${key}=${val}"
    # Debug
    # echo "VLESS_${key}=${val}"
  done

  if [[ "$VLESS_MULTIPLEX_ENABLE" == "true" && -n "$VLESS_FLOW" ]]; then
    exiterr "VLESS FLOW=$VLESS_FLOW does not work with MULTIPLEX"
  elif [[ "$VLESS_FLOW" != "xtls-rprx-vision"  ]]; then
    exiterr "VLESS FLOW=$VLESS_FLOW is not allowed. Allowed: xtls-rprx-vision"
  fi

  case "$VLESS_SECURITY" in
    reality)
      [[ -z "$VLESS_TYPE" || -z "$VLESS_SNI"  || -z "$VLESS_FLOW" || -z "$VLESS_FP" || -z "$VLESS_PBK" || -z "$VLESS_SID"  ]] && \
        exiterr "VLESS Reality PROXY_LINK is incorrect: empty TYPE or SNI or FLOW or FP or PBK or SID"
      VLESS_REALITY="\"reality\":{\"enabled\":true,\"public_key\":\"${VLESS_PBK}\",\"short_id\":\"${VLESS_SID}\"}"
    ;;
    tls)
      [[ -z "$VLESS_SNI" ]] && is_domain "$VLESS_HOST" && VLESS_SNI="$VLESS_HOST"
      [[ -z "$VLESS_TYPE" || -z "$VLESS_SNI" ||  -z "$VLESS_FP" ]] && \
        exiterr "VLESS TLS PROXY_LINK is incorrect: empty TYPE or SNI or FP"
    ;;
    *)
      exiterr "VLESS PROXY_LINK is incorrect: not support SECURITY=$VLESS_SECURITY"
    ;;
  esac

  [[ -n "$VLESS_ALPN" ]] && VLESS_ALPN="\"alpn\":[\"${VLESS_ALPN//,/\",\"}\"],"

  # Export PROXY_OUTBOUND
  export PROXY_OUTBOUND="{\"tag\":\"${TAG}\",\"type\":\"vless\",\"server\":\"${VLESS_HOST}\",
  \"server_port\":${VLESS_PORT},\"uuid\":\"${VLESS_UUID}\",\"flow\":\"$VLESS_FLOW\",
  \"network\":\"$VLESS_TYPE\",\"packet_encoding\":\"xudp\",\"tcp_fast_open\":true,\"tcp_multi_path\":true,
  \"tls\":{\"enabled\":true,\"insecure\":false,\"server_name\":\"${VLESS_SNI}\",${VLESS_ALPN}
  \"utls\":{\"enabled\":true,\"fingerprint\":\"${VLESS_FP}\"},${VLESS_REALITY}},
  \"multiplex\":{\"enabled\":${VLESS_MULTIPLEX_ENABLE},\"protocol\":\"${VLESS_MULTIPLEX_PROTO}\",
  \"padding\":false,\"brutal\":{\"enabled\":false}}}"
}

vless_parse_link "$1" "$2"
