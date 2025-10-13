#!/usr/bin/env bash
# The output is the sing-box dns params (type, server, server_port and path)

dns_params_parser() {
  local DNS_VAR_NAME="$1"
  local DNS_URL="$2"
  local DNS_URL_DEFAULT="$3"
  local DNS_TYPE DNS_SERVER DNS_SERVER_PORT DNS_PATH

  if [[ -z "$DNS_URL" && -n "$DNS_URL_DEFAULT" ]]; then
    warn "${DNS_VAR_NAME} set by default on: $DNS_URL_DEFAULT"
    dns_params_parser "$DNS_VAR_NAME" "$DNS_URL_DEFAULT"
    return 1
  fi

  case "$DNS_URL" in
    local)
      export "${DNS_VAR_NAME}_TYPE=local"
      log "${DNS_VAR_NAME} accept: $DNS_URL"
    ;;
    tcp://*|udp://*|https://*|h3://*|tls://*|quic://*)
      if [[ "$DNS_URL" =~ ^([a-zA-Z0-9+.-]+)://([^:/]+)(:([0-9]+))?(/.*)?$ ]]; then
        DNS_TYPE="${BASH_REMATCH[1]}"
        DNS_SERVER="${BASH_REMATCH[2]}"
        DNS_SERVER_PORT="${BASH_REMATCH[4]}"
        DNS_PATH="${BASH_REMATCH[5]}"

        export "${DNS_VAR_NAME}_TYPE=${DNS_TYPE}"

        if ! is_ipv4 "$DNS_SERVER" && ! is_domain "$DNS_SERVER"; then
          exiterr "${DNS_VAR_NAME}_SERVER must be a valid domain or IPv4 address"
        fi
        export "${DNS_VAR_NAME}_SERVER=${DNS_SERVER}"

        if [[ -z "$DNS_SERVER_PORT" ]]; then
          case "$DNS_TYPE" in
            tcp|udp) DNS_SERVER_PORT="53" ;;
            https|h3) DNS_SERVER_PORT="443" ;;
            tls|quic) DNS_SERVER_PORT="853" ;;
          esac
        fi
        export "${DNS_VAR_NAME}_SERVER_PORT=${DNS_SERVER_PORT}"

        case "$DNS_TYPE" in
          https|h3) DNS_PATH="/dns-query" ;;
        esac
        export "${DNS_VAR_NAME}_PATH=${DNS_PATH}"
      else
        exiterr "${DNS_VAR_NAME} "
      fi
      log "${DNS_VAR_NAME} accept: $DNS_URL"
    ;;
    *)
      exiterr "${DNS_VAR_NAME} only supported: local, tcp://, udp://, https://, h3://, tls://, quic://"
    ;;
  esac
}

dns_params_parser "$1" "$2" "$3"

# Debug
# type_var="${2}_TYPE"
# server_var="${2}_SERVER"
# port_var="${2}_SERVER_PORT"
# path_var="${2}_PATH"
# echo "${type_var}: ${!type_var}"
# echo "${server_var}: ${!server_var}"
# echo "${port_var}: ${!port_var}"
# echo "${path_var}: ${!path_var}"
