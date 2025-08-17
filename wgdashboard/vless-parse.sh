#!/usr/bin/env bash
# vless-parse.sh

vless_parse_link (){
  [[ -z "$1" ]] && return

  local URL STRIPPED MAIN QUERY HOSTPORT

  URL="$1"
  # Remove the vless:// scheme
  STRIPPED="${URL#vless://}"
  # Separate the main && query part
  MAIN="${STRIPPED%%\?*}"
  QUERY="${STRIPPED#*\?}"
  QUERY="${QUERY%%#*}"

  # --- MAIN (uuid@host:port) ---
  VLESS_UUID="${MAIN%@*}"
  HOSTPORT="${MAIN#*@}"

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
    val="${val,,}" 

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
              if [[ ! "$val" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
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
              if [[ -n "$val" && ! "$val" =~ ^[A-Za-z0-9_-]+$ ]]; then
                exiterr "VLESS SID contains invalid characters"
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
          # Export QUERY variables
          declare "VLESS_${key}=${val}"
          # Debug
          # echo "VLESS_${key}=${val}"
        fi
      ;;
    esac
  done
}