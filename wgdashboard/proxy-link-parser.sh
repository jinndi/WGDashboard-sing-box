#!/usr/bin/env bash
# /proxy-link-parser.sh
# The output is the environment variable PROXY_INBOUND
exiterr(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") ❌ Error: $1"

}
vless_parse_link() {
  local PROXY_LINK STRIPPED MAIN QUERY HOSTPORT
  local VLESS_UUID VLESS_HOST VLESS_PORT
  local VLESS_SNI VLESS_PBK VLESS_SID VLESS_FP

  PROXY_LINK="$1"
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
  if [[ -z "$VLESS_HOST" || \
    ! "$VLESS_HOST" =~ ^(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|([0-9]{1,3}\.){3}[0-9]{1,3})$ ]]
  then
    exiterr "VLESS HOST must be a valid domain or IPv4 address"
  fi

  # Check VLESS_PORT (must be a number from 1 to 65535)
  if [[ -z "$VLESS_PORT" || ! "$VLESS_PORT" =~ ^[0-9]+$ ]] \
    || ((VLESS_PORT < 1 || VLESS_PORT > 65535))
  then
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
        [[ -n "$val" && "$val" != "reality" ]] && exiterr "VLESS SECURITY is not 'reality'"
      ;;
      TYPE)
        [[ -n "$val" && "$val" != "tcp" ]] && exiterr "VLESS TYPE is not 'tcp'"
      ;;
      ENCRYPTION)
        [[ -n "$val" && "$val" != "none" ]] && exiterr "VLESS ENCRYPTION is not 'none'"
      ;;
      PACKETENCODING)
        [[ -n "$val" && "$val" != "xudp" ]] && exiterr "VLESS PACKETENCODING is not 'xudp'"
      ;;
      FLOW)
        [[ -n "$val" && "$val" != "xtls-rprx-vision" ]] && exiterr "VLESS FLOW is not 'xtls-rprx-vision'"
      ;;
      *)
        if [[ "$key" =~ ^(SNI|PBK|SID|FP)$ ]]; then
          case "$key" in
            SNI)
              # Check for domain name (sub.domain.tld)
              if [[ ! "$val" =~ ^([a-z0-9-]+\.)+[a-z]{2,}$ ]]; then
                exiterr "VLESS SNI must be a valid domain"
              fi
            ;;
            PBK)
              # Length of public key X25519 = 32 bytes → in Base64 URL-safe 43 characters.
              if [[ ! "$val" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
                exiterr "VLESS PBK must be a 43-character Base64 URL-safe public key"
              fi  
            ;;
            SID)
              # May be empty, but if specified - only letters, numbers, hyphens or underscores
              if [[ ! "$val" =~ ^[0-9a-f]{0,16}$ ]]; then
                exiterr "VLESS SID must be 0–16 lowercase hex characters"
              fi
            ;;
            FP)
              # Fingerprint check
              if [[ ! "$val" =~ ^(chrome|firefox|edge|safari|360|qq|ios|android|random|randomized)$ ]]; then
                echo -e "$(date "+%Y-%m-%d %H:%M:%S") Warn: Set VLESS fingerprint by default on 'chrome'"
                val=chrome
              fi
            ;;
          esac
          # Declare QUERY variable
          declare "VLESS_${key}=${val}"
          # Debug
          # echo "VLESS_${key}=${val}"
        fi
      ;;
    esac
  done
  # Export PROXY_INBOUND
  export PROXY_INBOUND=",{\"tag\":\"proxy\",\"type\":\"vless\",\"server\":\"${VLESS_HOST}\",\"server_port\":${VLESS_PORT},
  \"uuid\":\"${VLESS_UUID}\",\"flow\":\"xtls-rprx-vision\",\"packet_encoding\":\"xudp\",\"domain_resolver\":\"dns-proxy\",
  \"tls\":{\"enabled\":true,\"insecure\":false,\"server_name\":\"${VLESS_SNI}\",
  \"utls\":{\"enabled\":true,\"fingerprint\":\"${VLESS_FP}\"},
  \"reality\":{\"enabled\":true,\"public_key\":\"${VLESS_PBK}\",\"short_id\":\"${VLESS_SID}\"}},
  \"multiplex\":{\"enabled\": true}}"
}

ss2022_parse_link() {
  local PROXY_LINK STRIPPED MAIN QUERY
  local CREDS HOSTPORT
  local SS_METHOD SS_PASSWORD SS_HOST SS_PORT

  PROXY_LINK="$1"

  # Remove ss:// prefix
  STRIPPED="${PROXY_LINK#ss://}"

  # --- Split query if exists ---
  if [[ "$STRIPPED" == *\?* ]]; then
    MAIN="${STRIPPED%%\?*}"
    QUERY="${STRIPPED#*\?}"
  else
    MAIN="$STRIPPED"
    QUERY=""
  fi

  # --- Split credentials and host:port ---
  CREDS="${MAIN%@*}"       # method:password (possibly Base64)
  HOSTPORT="${MAIN##*@}"   # host:port

  # --- Decode Base64 if needed ---
  if ! [[ "$CREDS" == *:* ]]; then
    DECODED=$(echo "$CREDS" | openssl base64 -d -A 2>/dev/null)
    if [[ $? -ne 0 || "$DECODED" != *:* ]]; then
      exiterr "Failed to decode Shadowsocks Base64 part or invalid format"
    fi
    CREDS="$DECODED"
  fi

  SS_METHOD="${CREDS%%:*}"
  SS_METHOD="${SS_METHOD,,}"
  SS_PASSWORD="${CREDS#*:}"
  SS_HOST="${HOSTPORT%%:*}"
  SS_PORT="${HOSTPORT##*:}"

  # Debug
  # echo "SS_METHOD=$SS_METHOD"
  # echo "SS_PASSWORD=$SS_PASSWORD"
  # echo "SS_HOST=$SS_HOST"
  # echo "SS_PORT=$SS_PORT"

  # Checking SS_METHOD
  [[ -z "$SS_METHOD" ]] && exiterr "Shadowsocks METHOD is empty"
  [[ "$SS_METHOD" != "2022-blake3-aes-128-gcm" ]] && exiterr "Shadowsocks METHOD must be 2022-blake3-aes-128-gcm"

  # Checking SS_PASSWORD Base64
  [[ -z "$SS_PASSWORD" ]] && exiterr "Shadowsocks PASSWORD is empty"
  if [[ ! "$SS_PASSWORD" =~ ^[A-Za-z0-9+/]{22}==$ ]]; then
    exiterr "Shadowsocks PASSWORD is invalid for 2022-blake3-aes-128-gcm (must be 16-byte Base64 key)"
  fi

  # Checking SS_HOST (domain or IP)
  if [[ -z "$SS_HOST" || \
    ! "$SS_HOST" =~ ^(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|([0-9]{1,3}\.){3}[0-9]{1,3})$ ]]
  then
    exiterr "Shadowsocks HOST must be a valid domain or IPv4 address"
  fi

  # Check SS_PORT (must be a number from 1 to 65535)
  if [[ -z "$SS_PORT" || ! "$SS_PORT" =~ ^[0-9]+$ ]] \
    || ((SS_PORT < 1 || SS_PORT > 65535))
  then
    exiterr "Shadowsocks PORT is empty or not a valid port (1-65535)"
  fi

  # Parse optional query
  if [[ -n "$QUERY" ]]; then
    IFS='&' read -ra PAIRS <<< "$QUERY"
    for kv in "${PAIRS[@]}"; do
      key="${kv%%=*}"
      val="${kv#*=}"
      case "${key,,}" in
        network)
          [[ ! "${val,,}" =~ tcp ]] && exiterr "Shadowsocks network must include tcp"
        ;;
      esac
    done
  fi

  # Export PROXY_INBOUND
  export PROXY_INBOUND=",{\"tag\":\"proxy\",\"type\":\"shadowsocks\",\"server\":\"${SS_HOST}\",
  \"server_port\":${SS_PORT},\"method\":\"${SS_METHOD}\",\"password\":\"${SS_PASSWORD}\",
  \"network\":\"tcp\",\"multiplex\":{\"enabled\": true}}"
}

gen_proxy_inbound() {
  local PROXY_LINK prefix

  PROXY_LINK="${1:-}"
  
  [[ -z "$PROXY_LINK" ]] && return

  if ! echo "$PROXY_LINK" | grep -qiE '^(vless://|ss://)'; then
    exiterr "The PROXY_LINK does NOT start with vless:// or ss://"
  fi

  prefix="${PROXY_LINK%%://*}"
  prefix="${prefix,,}"
  
  case "$prefix" in
    vless)
      vless_parse_link "$PROXY_LINK"
    ;;
    ss)
      ss2022_parse_link "$PROXY_LINK"
    ;;
  esac
}

gen_proxy_inbound "$1"