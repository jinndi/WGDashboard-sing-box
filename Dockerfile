# https://github.com/SagerNet/sing-box/releases
ARG SINGBOX_VERSION="v1.12.1"

FROM ghcr.io/sagernet/sing-box:${SINGBOX_VERSION} AS sing-box

FROM docker.io/donaldzou/wgdashboard:latest

COPY --from=sing-box /usr/local/bin/sing-box /bin/sing-box

COPY ./entrypoint.sh /entrypoint.sh

RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]