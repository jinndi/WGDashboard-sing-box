#!/usr/bin/env bash
# The output is the environment variable PROXY_OUTBOUND or PROXY_ENDPOINT

urldecode(){
  jq -rn --arg x "${1}" '$x|@uri|@sh'
}

vless_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN QUERY HOSTPORT
  local VLESS_UUID VLESS_HOST VLESS_PORT
  local VLESS_SNI VLESS_PBK VLESS_SID VLESS_FP VLESS_ALPN
  local VLESS_REALITY
  local VLESS_MULTIPLEX_ENABLE="false"
  local VLESS_MULTIPLEX_PROTO="h2mux"

  PROXY_LINK="$1"
  TAG="$2"
  # Remove the vless:// scheme
  STRIPPED="${PROXY_LINK#vless://}"
  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  QUERY="${STRIPPED#*\?}"
  QUERY="${QUERY%%#*}"

  # --- MAIN (uuid@host:port) ---
  VLESS_UUID="${MAIN%@*}"
  HOSTPORT="${MAIN#*@}"
  # Declare MAIN
  VLESS_UUID="${VLESS_UUID%%@*}"
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
        val="$(urldecode "$val")"
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

  # Decode Base64 if needed
  if ! [[ "$CREDS" == *:* ]]; then
    DECODED=$(echo "$CREDS" | openssl base64 -d -A 2>/dev/null)
    if [[ $? -ne 0 || "$DECODED" != *:* ]]; then
      exiterr "Failed to decode Shadowsocks Base64 part or invalid format"
    fi
    CREDS="$DECODED"
  fi

  SS_METHOD="${CREDS%%:*}"
  SS_METHOD="${SS_METHOD,,}"
  SS_PASSWORD="$(urldecode "${CREDS#*:}")"
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
      if [[ ! "$SS_PASSWORD" =~ ^[A-Za-z0-9+/]{22}==$ ]]; then
        exiterr "Shadowsocks-2022 PASSWORD for blake3-aes-128-gcm must be: 16-byte Base64 key"
      fi
    ;;
    2022-blake3-aes-256-gcm)
      if [[ ! "$SS_PASSWORD" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        exiterr "Shadowsocks-2022 PASSWORD for blake3-aes-256-gcm must be: 32-byte Base64 key"
      fi
    ;;
    2022-blake3-chacha20-poly1305)
      if [[ "$SS_PASSWORD" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        exiterr "Shadowsocks-2022 PASSWORD for blake3-chacha20-poly1305 must be: 32-byte Base64 key"
      fi
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
  QUERY="${STRIPPED#*\?}"

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

wg_parse_link(){
  local PROXY_LINK TAG STRIPPED MAIN QUERY
  local WG_HOST WG_PORT
  local WG_PK WG_LOCAL_ADDRESS WG_PEER_PUBLIC_KEY WG_MTU

  PROXY_LINK="$1"
  TAG="$2"

  # Remove prefix (wg://)
  STRIPPED="${PROXY_LINK#wg://}"

  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  QUERY="${STRIPPED#*\?}"

  # Split host and port
  WG_HOST="${MAIN%%:*}"
  WG_PORT="${MAIN##*:}"

  # Debug
  # echo "WG_HOST=$WG_HOST"
  # echo "WG_PORT=$WG_PORT"

  # Validation HOST PORT
  if [[ -z "$WG_HOST" ]]; then
    exiterr "WG HOST is empty"
  fi
  if ! is_port "$WG_PORT"; then
    exiterr "WG PORT is empty or not a valid port (1-65535)"
  fi

  # Parse optional query
  if [[ -n "$QUERY" ]]; then
    IFS='&' read -ra PAIRS <<< "$QUERY"
    for kv in "${PAIRS[@]}"; do
      key="${kv%%=*}"
      key="${key^^}"
      val="${kv#*=}"
      val="$(urldecode "${val}")"
      case "$key" in
        PK)
          [[ -z "$val" ]] && exiterr "WG pk (private key) is empty"
        ;;
        LOCAL_ADDRESS)
          [[ -z "$val" ]] && exiterr "WG local_address is empty"
          if ! is_ip_cidr_list "$val"; then
            exiterr "WG local_address must be a valid ipv4/ipv6 adresses"
          fi
        ;;
        PEER_PUBLIC_KEY)
          [[ -z "$val" ]] && exiterr "WG peer_public_key is empty"
        ;;
        MTU)
          if [[ -z "$val" ]]; then
            warn "WG MTU set by default on: 1408"
            val=1408
          else
            if is_port "$val"; then
              if ((val < 1280 )); then
                warn "WG MTU < 1280, set by default on: 1280"
                val=1280
              fi
              if ((val > 1420 )); then
                warn "WG MTU > 1420, set by default on: 1420"
                val=1420
              fi
            else
              warn "WG MTU is not allowed, set by default on: 1408"
              val=1408
            fi
          fi
        ;;
        *)
          continue
        ;;
    esac
    # Declare QUERY variable
    declare "WG_${key}=${val}"
    # Debug
    # echo "WG_${key}=${val}"
    done
  fi

  if [[ -z "$WG_PK" || -z "$WG_LOCAL_ADDRESS" || -z "$WG_PEER_PUBLIC_KEY" ]]
    exiterr "WG PROXY_LINK is incorrect: empty PK or LOCAL_ADDRESS or PEER_PUBLIC_KEY"
  fi

  if [[ -z "$WG_MTU" ]]; then
    warn "WG MTU set by default on: 1408"
    WG_MTU=1408
  fi

  # Build and export PROXY_ENDPOINT
  PROXY_ENDPOINT="{\"tag\":\"${TAG}\",\"type\":\"wireguard\",\
  \"system\":false,"mtu":${WG_MTU},\"tcp_fast_open\":true,
  \"address\":[${WG_LOCAL_ADDRESS//,/\",\"}],\"private_key\":\"${WG_PK}\",
  \"peers\":[{"address": \"${WG_HOST}\","port": ${WG_PORT},
  \"public_key\":\"${WG_PEER_PUBLIC_KEY}\",\"allowed_ips\":[\"0.0.0.0/0\",\"::/0\"],
  \"persistent_keepalive_interval\":21}],\"udp_timeout\":\"5m0s\"}"

  export PROXY_ENDPOINT
}

gen_proxy_outbound(){
  local tag prefix

  [[ -z "$PROXY_LINK" ]] && return

  tag="proxy"
  [[ "$WARP_OVER_PROXY" == "true" ]] && tag="proxy1"

  prefix="${PROXY_LINK%%://*}"
  prefix="${prefix,,}"

  case "$prefix" in
    vless)
      vless_parse_link "$PROXY_LINK" "$tag"
    ;;
    ss)
      ss2022_parse_link "$PROXY_LINK" "$tag"
    ;;
    socks5)
      socks5_parse_link "$PROXY_LINK" "$tag"
    ;;
    wg)
      wg_parse_link "$PROXY_LINK" "$tag"
    ;;
  esac
}

gen_proxy_outbound
