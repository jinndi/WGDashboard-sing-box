# Release links:
# https://github.com/SagerNet/sing-box/releases
# https://github.com/donaldzou/WGDashboard/releases

ARG singbox_version="v1.12.8"
ARG wgdashboard_version="v4.3.0.1"

# sing-box image to copy the binary
FROM ghcr.io/sagernet/sing-box:${singbox_version} AS sing-box

# WGDashboard image to copy the binary and app source
FROM ghcr.io/wgdashboard/wgdashboard:${wgdashboard_version} AS wgdashboard

# Building WGDashboard-sing-box
FROM alpine:3.22
LABEL maintainer="Jinndi <alncores@gmail.com>"

# Environment variables
ENV SINGBOX_TUN_NAME=singbox \
    WGDASH=/opt/wgdash

# Install dependencies
RUN apk update && apk add --no-cache sudo bash curl iptables iproute2 \
  procps tzdata wireguard-tools openresolv openrc \
  python3 py3-psutil py3-bcrypt openssl jq inotify-tools

# Create directories
RUN mkdir -p "$WGDASH" /data /etc/wireguard /etc/amnezia/amneziawg

# Copy binaries to container
COPY --from=sing-box /usr/local/bin/sing-box /usr/bin/sing-box
COPY --from=wgdashboard /usr/bin/amneziawg-go /usr/bin/amneziawg-go
COPY --from=wgdashboard /usr/bin/awg /usr/bin/awg
COPY --from=wgdashboard /usr/bin/awg-quick /usr/bin/awg-quick
# Copy app source
COPY --from=wgdashboard /opt/wgdashboard/src "$WGDASH"
# Copy scripts and sysctl config to container
COPY ./scripts/ /scripts/
COPY ./entrypoint.sh /entrypoint.sh
COPY ./sysctl.conf /etc/sysctl.conf

WORKDIR $WGDASH

# Install WGDashboard and chmod /scripts
RUN rm -rf ./venv ;\
  python3 -m venv ./venv ;\
  mv /usr/lib/python3.12/site-packages/psutil* ./venv/lib/python3.12/site-packages ;\
  mv /usr/lib/python3.12/site-packages/bcrypt* ./venv/lib/python3.12/site-packages ;\
  . ./venv/bin/activate ;\
  bash ./wgd.sh install ;\
  rm -rf ./wg-dashboard.ini ./db ./static/app ./static/client ;\
  rm -rf ./__pycache__ /var/cache/apk/* /root/.cache /root/.local ;\
  find /scripts -type f -exec chmod +x {} ';'

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD sh -c 'pgrep gunicorn > /dev/null && pgrep tail > /dev/null' || exit 1

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
