#!/usr/bin/env bash
# vless-parse.sh

log(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

if [[ -n "$1" ]]; then
  URL="$1"
else
  log "Error: VLESS URL not passed in $(realpath "${BASH_SOURCE[0]}")"
  exit 1
fi

# Remove the vless:// scheme
STRIPPED="${URL#vless://}"

# Separate the main part from the query
MAIN="${STRIPPED%%\?*}"
QUERY="${STRIPPED#*\?}"
QUERY="${QUERY%%#*}"

# --- MAIN (uuid@host:port) ---
UUID="${MAIN%@*}"
UUID="${UUID%%@*}"
HOSTPORT="${MAIN#*@}"
HOST="${HOSTPORT%%:*}"
PORT="${HOSTPORT##*:}"

# Check UUID (must be UUID v4)
if [[ -z "$UUID" || \
  ! "$UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]]
then
  log "Error: VLESS UUID is empty or not a valid UUIDv4"
  exit 1
fi

# Checking HOST (domain or IP)
if [[ -z "$HOST" || \
  ! "$HOST" =~ ^(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|([0-9]{1,3}\.){3}[0-9]{1,3})$ ]]
then
  log "Error: VLESS HOST must be a valid domain or IPv4 address"
  exit 1
fi

# Check PORT (must be a number from 1 to 65535)
if [[ -z "$PORT" || ! "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  log "Error: VLESS PORT is empty or not a valid port (1-65535)"
  exit 1
fi

# Export MAIN variables
export VLESS_UUID="$UUID"
export VLESS_HOST="$HOST"
export VLESS_PORT="$PORT"
# Debug
# echo "VLESS_UUID=$UUID"
# echo "VLESS_HOST=$HOST"
# echo "VLESS_PORT=$PORT"

# --- QUERY (key=value) ---
IFS='&' read -ra PAIRS <<< "$QUERY"
for kv in "${PAIRS[@]}"; do
  key="${kv%%=*}"
  key="${key^^}"
  val="${kv#*=}"
  val="${val,,}" 

  case "$key" in
    SECURITY)
      [[ "$val" != "reality" ]] && log "Error: VLESS SECURITY is not 'reality'" && exit 1
    ;;
    TYPE)
      [[ "$val" != "tcp" ]] && log "Error: VLESS TYPE is not 'tcp'" && exit 1
    ;;
    ENCRYPTION)
      [[ "$val" != "none" ]] && log "Error: VLESS ENCRYPTION is not 'none'" && exit 1
    ;;
    PACKETENCODING)
      [[ "$val" != "xudp" ]] && log "Error: VLESS PACKETENCODING is not 'xudp'" && exit 1
    ;;
    FLOW)
      [[ "$val" != "xtls-rprx-vision" ]] && log "VLESS FLOW is not 'xtls-rprx-vision'" && exit 1
    ;;
    *)
      if [[ "$key" =~ ^(SNI|PBK|SID|FP)$ ]]; then
        case "$key" in
          SNI)
            # Check for domain name (sub.domain.tld)
            if [[ ! "$val" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
              log "Error: VLESS SNI must be a valid domain"
              exit 1
            fi
          ;;
          PBK)
            # Length of public key X25519 = 32 bytes → in Base64 URL-safe 43 characters.
            if [[ ! "$val" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
              log "Error: VLESS PBK must be a 43-character Base64 URL-safe public key"
              exit 1
            fi  
          ;;
          SID)
            # May be empty, but if specified - only letters, numbers, hyphens or underscores
            if [[ -n "$val" && ! "$val" =~ ^[A-Za-z0-9_-]+$ ]]; then
              log "Error: VLESS SID contains invalid characters"
              exit 1
            fi
          ;;
          FP)
            # Fingerprint check
            if [[ ! "$val" =~ ^(chrome|firefox|edge|safari|360|qq|ios|android|random|randomized)$ ]]; then
              log "Warn: Set VLESS fingerprint by default on 'chrome'"
              val=chrome
            fi
          ;;
        esac
        # Export QUERY variables
        export "VLESS_${key}"="${val}"
        # Debug
        # echo "VLESS_${key}=${val}"
      fi
    ;;
  esac
done

exit 0