#!/usr/bin/env bash

gen_proxy_outbound(){
  local tag prefix

  [[ -z "$PROXY_LINK" ]] && return

  tag="proxy"
  [[ "$WARP_OVER_PROXY" == "true" ]] && tag="proxy1"

  prefix="${PROXY_LINK%%://*}"
  prefix="${prefix,,}"

  case "$prefix" in
    vless)
      . ./link_parsers/vless.sh "$PROXY_LINK" "$tag"
    ;;
    ss)
      . ./link_parsers/ss2022.sh "$PROXY_LINK" "$tag"
    ;;
    socks5)
      . ./link_parsers/socks5.sh "$PROXY_LINK" "$tag"
    ;;
    wg)
      . ./link_parsers/wg.sh "$PROXY_LINK" "$tag"
    ;;
    trojan)
      . ./link_parsers/trojan.sh "$PROXY_LINK" "$tag"
    ;;
    hy2)
      . ./link_parsers/hy2.sh "$PROXY_LINK" "$tag"
    ;;
    tuic)
      . ./link_parsers/tuic.sh "$PROXY_LINK" "$tag"
    ;;
  esac
}

gen_proxy_outbound
