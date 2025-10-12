#!/usr/bin/env bash

register_and_enabled_warp() {
  local private_key public_key peer_address address_ipv4 address_ipv6
  local pubkey response id token success

  private_key=$(wg genkey)

  pubkey=$(echo "${private_key}" | wg pubkey)

  ins() {
    curl -s --connect-timeout 3 --max-time 6 \
      -H 'user-agent: okhttp/3.12.1' \
      -H 'content-type: application/json' \
      -X "$1" "https://api.cloudflareclient.com/v0i1909051800/$2" "${@:3}";
  }

  sec() { ins "$1" "$2" -H "authorization: Bearer $3" "${@:4}"; }

  response=$(ins POST "reg" -d "{\"install_id\":\"\",\"tos\":\"$(date -u +%FT%T.000Z)\",\"key\":\"${pubkey}\",\"fcm_token\":\"\",\"type\":\"ios\",\"locale\":\"en_US\"}")

  if [[ -z "$response" ]]; then
    warn "Failed to register WARP. No response from API!"
    return 1
  fi

  success=$(echo "$response" | jq -r '.success')

  if [[ "$success" != "true" ]]; then
    warn "Failed to register WARP. API did not return success true!"
    return 1
  fi

  id=$(echo "$response" | jq -r '.result.id')
  token=$(echo "$response" | jq -r '.result.token')

  if [[ -z "$id" || -z "$token" ]]; then
    warn "Failed to get params WARP. Missing id or token!"
    return 1
  fi

  response=$(sec PATCH "reg/${id}" "$token" -d '{"warp_enabled":true}')

  if [[ -z "$response" ]]; then
    warn "Failed to enable WARP. No response from API!"
    return 1
  fi

  success=$(echo "$response" | jq -r '.success')

  if [[ "$success" != "true" ]]; then
    warn "Failed to enable WARP. API did not return success true!"
    return 1
  fi

  public_key=$(echo "$response" | jq -r '.result.config.peers[0].public_key')
  peer_address="engage.cloudflareclient.com"
  #$(echo "$response" | jq -r '.result.config.peers[0].endpoint.v4' | cut -d: -f1)
  address_ipv4=$(echo "$response" | jq -r '.result.config.interface.addresses.v4')
  address_ipv6=$(echo "$response" | jq -r '.result.config.interface.addresses.v6')

  if [[ -z "$public_key" || -z "$peer_address" || -z "$address_ipv4" || -z "$address_ipv6" ]]; then
    warn "Failed to get params WARP. Missing public_key, peer_address, address_ipv4 or address_ipv6!"
    return 1
  fi

  echo "$private_key|$public_key|$peer_address|$address_ipv4|$address_ipv6"
  return 0
}

create_warp_endpoint() {
  local FILE_ENDPOINT ARGS EXTRA

  FILE_ENDPOINT="$1"
  ARGS="$2"
  EXTRA="$3"

  IFS="|" read -r tag private_key public_key peer_address address_ipv4 address_ipv6 <<< "$ARGS"

cat <<ENDPOINT > "$FILE_ENDPOINT"
{
  "type": "wireguard",
  "tag": "${tag}",
  "system": false,
  "mtu": 1280,
  "address": ["${address_ipv4}/24", "${address_ipv6}/64"],
  "private_key": "${private_key}",
  "peers": [
    {
      "address": "${peer_address}",
      "port": 500,
      "public_key": "${public_key}",
      "allowed_ips": ["0.0.0.0/0", "::/0"],
      "persistent_keepalive_interval": 21
    }
  ],
  "udp_timeout": "5m0s"
  ${EXTRA}
}
ENDPOINT
}

generate_warp_endpoint() {
  local ARGS_PROXY ARGS_DIRECT status EXTRA

  ARGS_PROXY=$(register_and_enabled_warp)
  status=$?
  [[ $status -ne 0 ]] && echo -e "$ARGS_PROXY" && return 1

  ARGS_DIRECT=$(register_and_enabled_warp)
  status=$?
  [[ $status -ne 0 ]] && echo -e "$ARGS_DIRECT" && return 1

  WARP_ENDPOINT="${WARP_ENDPOINT:-/data/warp/endpoint}"

  mkdir -p "$(dirname "$WARP_ENDPOINT")"

  create_warp_endpoint "$WARP_ENDPOINT" "proxy|$ARGS_PROXY"

  EXTRA=',"detour": "proxy1"'
  create_warp_endpoint "${WARP_ENDPOINT}.over_proxy" "proxy|$ARGS_PROXY" "$EXTRA"

  create_warp_endpoint "${WARP_ENDPOINT}.over_direct" "direct|$ARGS_DIRECT"

  return 0
}

# shellcheck disable=SC2034
if ! generate_warp_endpoint; then
  WARP_OVER_DIRECT=false
  WARP_OVER_PROXY=false
fi
