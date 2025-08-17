#!/usr/bin/env bash
# vless-parse.sh

exiterr(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") Error: VLESS $1"
  exit 1
}

if [[ -n "$1" ]]; then
  URL="$1"
else
  exiterr "VLESS URL not passed in $(realpath "${BASH_SOURCE[0]}")"
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
  exiterr "UUID is empty or not a valid UUIDv4"
fi

# Checking HOST (domain or IP)
if [[ -z "$HOST" || \
  ! "$HOST" =~ ^(([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|([0-9]{1,3}\.){3}[0-9]{1,3})$ ]]
then
  exiterr "HOST must be a valid domain or IPv4 address"
fi

# Check PORT (must be a number from 1 to 65535)
if [[ -z "$PORT" || ! "$PORT" =~ ^[0-9]+$ ]] || ((PORT < 1 || PORT > 65535)); then
  exiterr "PORT is empty or not a valid port (1-65535)"
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
      [[ -n "$val" && "$val" != "reality" ]] && exiterr "SECURITY is not 'reality'"
    ;;
    TYPE)
      [[ -n "$val" && "$val" != "tcp" ]] && exiterr "TYPE is not 'tcp'"
    ;;
    ENCRYPTION)
      [[ -n "$val" && "$val" != "none" ]] && exiterr "ENCRYPTION is not 'none'"
    ;;
    PACKETENCODING)
      [[ -n "$val" && "$val" != "xudp" ]] && exiterr "PACKETENCODING is not 'xudp'"
    ;;
    FLOW)
      [[ -n "$val" && "$val" != "xtls-rprx-vision" ]] && exiterr "FLOW is not 'xtls-rprx-vision'"
    ;;
    *)
      if [[ "$key" =~ ^(SNI|PBK|SID|FP)$ ]]; then
        case "$key" in
          SNI)
            # Check for domain name (sub.domain.tld)
            if [[ ! "$val" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]; then
              exiterr "SNI must be a valid domain"
            fi
          ;;
          PBK)
            # Length of public key X25519 = 32 bytes → in Base64 URL-safe 43 characters.
            if [[ ! "$val" =~ ^[A-Za-z0-9_-]{43}$ ]]; then
              exiterr "PBK must be a 43-character Base64 URL-safe public key"
            fi  
          ;;
          SID)
            # May be empty, but if specified - only letters, numbers, hyphens or underscores
            if [[ -n "$val" && ! "$val" =~ ^[A-Za-z0-9_-]+$ ]]; then
              exiterr "SID contains invalid characters"
            fi
          ;;
          FP)
            # Fingerprint check
            if [[ ! "$val" =~ ^(chrome|firefox|edge|safari|360|qq|ios|android|random|randomized)$ ]]; then
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