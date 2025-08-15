# https://github.com/SagerNet/sing-box/releases
# https://github.com/donaldzou/WGDashboard/releases
ARG singbox_version="v1.12.1" \
    wgdashboard_version="v4.2.5"

FROM ghcr.io/sagernet/sing-box:${singbox_version} AS sing-box

FROM docker.io/donaldzou/wgdashboard:${wgdashboard_version}

COPY --from=sing-box /usr/local/bin/sing-box /bin/sing-box

COPY ./sysctl.conf /etc/sysctl.conf

COPY ./entrypoint.sh /entrypoint.sh

RUN chmod a+x /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]