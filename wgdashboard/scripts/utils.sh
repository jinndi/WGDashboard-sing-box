#!/bin/bash

log() { echo -e "$(date "+%Y-%m-%d %H:%M:%S") $1" >&2;}

warn() { log "⚠️ WARN: $1" >&2; }

exiterr() { log "❌ ERROR: $1"; exit 1 >&2; }

is_port() {
  local port="$1"
  if [[ ! "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    return 1
  else
    return 0
  fi
}

is_ipv4() {
  local ip="$1"
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    [[ "$octet" != "0" && "$octet" =~ ^0 ]] && return 1
    dec_octet=$((10#$octet))
    (( octet >= 0 && octet <= 255 )) || return 1
  done
  return 0
}

is_ipv4_cidr() {
  local cidr="$1"
  [[ $cidr =~ ^([^/]+)/([0-9]{1,2})$ ]] || return 1
  local ip="${BASH_REMATCH[1]}"
  local mask="${BASH_REMATCH[2]}"
  is_ipv4 "$ip" || return 1
  (( mask >= 0 && mask <= 32 )) || return 1
  return 0
}

is_domain() {
  local d="$1"
  idn2 "$d" >/dev/null 2>&1 || return 1
  [[ $d =~ ^([a-zA-Z0-9]([a-z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$ ]] || return 1
  (( ${#d} <= 253 )) || return 1
  return 0
}

is_valid_tun_name() {
  local name="$1"
  [[ $name =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]]
}

get_public_ipv4() {
  local public_ip
  public_ip="$(curl -4 -s ip.sb)"
  [ -z "$public_ip" ] && public_ip="$(curl -4 -s ifconfig.me)"
  [ -z "$public_ip" ] && public_ip="$(curl -4 -s https://api.ipify.org)"
  is_ipv4 "$public_ip" || public_ip=""
  echo "$public_ip"
}
