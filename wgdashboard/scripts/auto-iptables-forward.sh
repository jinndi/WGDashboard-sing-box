#!/bin/bash

# Interface with allowed traffic
ALLOW_FORWARD=${ALLOW_FORWARD:-}

WATCH_DIRS=("/etc/wireguard" "/etc/amnezia/amneziawg")

# Interface with allowed traffic (exception)
EXEMPT_INTERFACE="${SINGBOX_TUN_NAME-singbox}"

# Function to add/delete iptables a rules
apply_forward_rules() {
  local WG_INTERFACE="$1"
  local action="$2" # -A or -D

  [[ -z "$WG_INTERFACE" ]] || [[ -z "$action" ]] && \
    exiterr "[auto-iptables-forward.sh] Usage: apply_forward_rules <WG_INTERFACE> <-A|-D>"

  [[ -z "$EXEMPT_INTERFACE" ]] && exiterr "[auto-iptables-forward.sh] EXEMPT_INTERFACE is not set"

  # --- 1. Allow traffic to/from the exempt interface (singbox) ---
  iptables "$action" FORWARD -i "$WG_INTERFACE" -o "$EXEMPT_INTERFACE" -j ACCEPT || true
  iptables "$action" FORWARD -i "$EXEMPT_INTERFACE" -o "$WG_INTERFACE" -j ACCEPT || true

  if [[ -n "$ALLOW_FORWARD" ]] && [[ ",${ALLOW_FORWARD// /}," =~ ,$WG_INTERFACE, ]]; then
    # --- 2. Allow all traffic if WG_INTERFACE is in ALLOW_FORWARD ---
    iptables "$action" FORWARD -i "$WG_INTERFACE" -j ACCEPT || true
    iptables "$action" FORWARD -o "$WG_INTERFACE" -j ACCEPT || true
  else
    # --- 3. Block peer-to-peer traffic inside the WireGuard interface ---
    iptables "$action" FORWARD -i "$WG_INTERFACE" -o "$WG_INTERFACE" -j DROP || true
    # --- 4. Block all traffic from WG_INTERFACE to all other interfaces except EXEMPT_INTERFACE ---
    iptables "$action" FORWARD -i "$WG_INTERFACE" ! -o "$EXEMPT_INTERFACE" -j DROP || true
    iptables "$action" FORWARD ! -i "$EXEMPT_INTERFACE" -o "$WG_INTERFACE" -j DROP || true
  fi

  # --- 5. Logging ---
  if [[ "$action" == "-A" ]]; then
    log "[+] iptables FORWARD rules added for interface: $WG_INTERFACE"
  else
    log "[-] iptables FORWARD rules removed for interface: $WG_INTERFACE"
  fi
}

# Initial pass through files
for dir in "${WATCH_DIRS[@]}"; do
  [ -d "$dir" ] || continue
  for f in "$dir"/*.conf; do
    [ -f "$f" ] || continue
    iface=$(basename "$f" .conf)
    apply_forward_rules "$iface" "-A"
  done
done

# Start monitoring
inotifywait -m -e create -e delete "${WATCH_DIRS[@]}" --format '%e %w%f' |
while read -r event file; do
  case "$event" in
    CREATE|MOVED_TO)
      iface=$(basename "$file" .conf)
      [[ "$file" == *.conf ]] && apply_forward_rules "$iface" "-A"
    ;;
    DELETE|MOVED_FROM)
      iface=$(basename "$file" .conf)
      [[ "$file" == *.conf ]] && apply_forward_rules "$iface" "-D"
    ;;
  esac
done &
