#!/usr/bin/env bash

gen_proxy_outbound(){
  local tag prefix

  [[ -z "$PROXY_LINK" ]] && return

  if ! echo "$PROXY_LINK" | grep -qiE '^(vless://|ss://|socks5://|wg://|trojan://|hy2://|tuic://)'; then
    exiterr "PROXY_LINK does NOT start with vless:// ss:// socks5:// wg:// trojan:// hy2:// or tuic://"
  fi

  tag="proxy"
  if [[ -f "${WARP_ENDPOINT}.over_proxy" && "$WARP_OVER_PROXY" == "true" ]]; then
    tag="proxy1"
  fi

  prefix="${PROXY_LINK%%://*}"
  prefix="${prefix,,}"

  case "$prefix" in
    vless)
      . /scripts/link_parsers/vless.sh "$PROXY_LINK" "$tag"
    ;;
    ss)
      . /scripts/link_parsers/ss2022.sh "$PROXY_LINK" "$tag"
    ;;
    socks5)
      . /scripts/link_parsers/socks5.sh "$PROXY_LINK" "$tag"
    ;;
    wg)
      . /scripts/link_parsers/wg.sh "$PROXY_LINK" "$tag"
    ;;
    trojan)
      . /scripts/link_parsers/trojan.sh "$PROXY_LINK" "$tag"
    ;;
    hy2)
      . /scripts/link_parsers/hy2.sh "$PROXY_LINK" "$tag"
    ;;
    tuic)
      . /scripts/link_parsers/tuic.sh "$PROXY_LINK" "$tag"
    ;;
  esac
}

gen_proxy_outbound
