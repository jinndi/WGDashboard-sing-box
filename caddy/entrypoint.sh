#!/bin/bash

exiterr(){
  echo -e "$(date "+%Y-%m-%d %H:%M:%S") ❌ Error: $1"
  exit 1
}

/usr/bin/caddy stop

echo -e "\n------------------------- START ----------------------------"

DOMAIN="${DOMAIN:-}"
[[ -z "$DOMAIN" ]] && exiterr "DOMAIN not set!"
[[ ! "$DOMAIN" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]] \
  && exiterr "DOMAIN must be a valid!"

EMAIL="${EMAIL:-}"
[[ -z "$EMAIL" ]] && exiterr "EMAIL not set!"
[[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] \
  && exiterr "EMAIL must be a valid!"

SERVICE_NAME="${SERVICE_NAME:-wgd}"
[[ ! "$SERVICE_NAME" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] \
  && exiterr "SERVICE_NAME must be a valid!"

SERVICE_PORT="${SERVICE_PORT:-10086}"
[[ ! "$SERVICE_PORT" =~ ^[0-9]+$ ]] || ((SERVICE_PORT < 1 || SERVICE_PORT > 65535)) \
  && exiterr "SERVICE_PORT must be a valid!"

CADDYFILE="/etc/caddy/Caddyfile"

mkdir -p "$(dirname "$CADDYFILE")"

cat > "$CADDYFILE" <<EOF
$DOMAIN

log {
  output stdout
  format console
  level WARN
}

tls $EMAIL

reverse_proxy $SERVICE_NAME:$SERVICE_PORT
EOF

if /usr/bin/caddy validate --config "$CADDYFILE" >/dev/null; then
  echo "✅ Caddyfile is valid"
else
  echo "❌ Invalid Caddyfile"
  exit 1
fi

sleep 2s

if ! pgrep -x "caddy" >/dev/null 2>&1; then
  echo "Format Caddyfile"
  /usr/bin/caddy fmt --overwrite >/dev/null
  echo "Launching Caddy"
  exec /usr/bin/caddy run -c "$CADDYFILE" -a caddyfile
else
  echo "Reload Caddy"
  /usr/bin/caddy reload
fi

echo "✅ Caddy launched"