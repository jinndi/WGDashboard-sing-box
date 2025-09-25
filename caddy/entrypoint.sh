#!/bin/bash

log(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1"
}

exiterr(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") ❌ Error: $1"
  exit 1
}

echo -e "\n--------------------------- START ------------------------------"

DOMAIN="${DOMAIN:-}"
[[ -z "$DOMAIN" ]] && exiterr "DOMAIN not set!"
[[ ! "$DOMAIN" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]] \
  && exiterr "DOMAIN must be a valid!"
log "Using DOMAIN: $DOMAIN"

EMAIL="${EMAIL:-}"
[[ -z "$EMAIL" ]] && exiterr "EMAIL not set!"
[[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] \
  && exiterr "EMAIL must be a valid!"
log "Using EMAIL: $EMAIL"

PROXY="${PROXY:-wgd:10086}"
[[ -z "$PROXY" ]] && exiterr "PROXY not set!"

CADDYFILE="/etc/caddy/Caddyfile"
mkdir -p "$(dirname "$CADDYFILE")"

cat > "$CADDYFILE" <<EOF
{
	email $EMAIL

	log default {
		output stdout
		format console
    level ERROR
	}
}

$DOMAIN {

  encode gzip

  tls {
    protocols tls1.3
  }

EOF

IFS=',' read -ra proxies_array <<< "$PROXY"

count=${#proxies_array[@]}

if (( count == 1 )); then
  echo "  reverse_proxy ${proxies_array[*]}" >> "$CADDYFILE"
else
  for entry in "${proxies_array[@]}"; do
    host_port="${entry%%/*}"
    host_port="${host_port,,}"
    path="${entry#*/}"

    # Validate path
    if [[ -z "$path" ]]; then
      exiterr "Path is missing in entry: $entry"
    fi
    if ! [[ "$path" =~ ^[a-zA-Z0-9/_-]+$ ]]; then
      exiterr "Invalid path format: $path"
    fi

    # Validate host:port
    if [[ "$host_port" == *:* ]]; then
      host="${host_port%%:*}"
      port="${host_port##*:}"

      if ! [[ "$port" =~ ^[0-9]{1,5}$ ]] || (( port < 1 || port > 65535 )); then
        exiterr "Invalid port: $host_port"
      fi
    else
      host="$host_port"
      port=""
    fi

    if ! [[ "$host" =~ ^[a-z0-9._-]+$ ]]; then
      exiterr "Invalid hostname/domain format: $host"
    fi

    log "✅ Accept Valid: $host_port/$path"

    # Generate route
    {
      echo "  route /$path* {"
      echo "    reverse_proxy $host_port"
      echo "  }"
      echo
    } >> "$CADDYFILE"
  done
fi

cat > "$CADDYFILE" <<EOFEND
  header {
    header_up Authorization { >Authorization }
    header_up Content-Type { >Content-Type }
    Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    X-Content-Type-Options nosniff
    X-Frame-Options SAMEORIGIN
    Referrer-Policy strict-origin-when-cross-origin
    -Server
    -X-Powered-By
  }

  respond "Not found!" 404
}
EOFEND


log "Validate Caddyfile"
if /usr/bin/caddy validate --config "$CADDYFILE" >/dev/null; then
  log "Caddyfile is valid"
else
  exiterr "Invalid Caddyfile"
fi

log "Format Caddyfile"
/usr/bin/caddy fmt "$CADDYFILE" --overwrite >/dev/null

log "Launching Caddy"
exec /usr/bin/caddy run -c "$CADDYFILE" -a caddyfile
