#!/usr/bin/env bash
# The output is the environment variable PROXY_ENDPOINT

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
  QUERY="${QUERY%%#*}"

  # Remove possible path after port
  MAIN="${MAIN%%/*}"

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
            exiterr "WG local_address must be a valid ipv4/ipv6 CIDR adresses"
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

  if [[ -z "$WG_PK" || -z "$WG_LOCAL_ADDRESS" || -z "$WG_PEER_PUBLIC_KEY" ]]; then
    exiterr "WG PROXY_LINK is incorrect: empty PK or LOCAL_ADDRESS or PEER_PUBLIC_KEY"
  fi

  if [[ -z "$WG_MTU" ]]; then
    warn "WG MTU set by default on: 1408"
    WG_MTU=1408
  fi

  # Build and export PROXY_ENDPOINT
  PROXY_ENDPOINT="{\"tag\":\"${TAG}\",\"type\":\"wireguard\",\
  \"system\":false,\"mtu\":${WG_MTU},\"tcp_fast_open\":true,
  \"address\":[\"${WG_LOCAL_ADDRESS//,/\",\"}\"],\"private_key\":\"${WG_PK}\",
  \"peers\":[{\"address\":\"${WG_HOST}\",\"port\":${WG_PORT},
  \"public_key\":\"${WG_PEER_PUBLIC_KEY}\",\"allowed_ips\":[\"0.0.0.0/0\",\"::/0\"],
  \"persistent_keepalive_interval\":21}],\"udp_timeout\":\"5m0s\"}"

  export PROXY_ENDPOINT
}

wg_parse_link "$1" "$2"
