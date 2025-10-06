# Release links:
# https://github.com/SagerNet/sing-box/releases
# https://github.com/WGDashboard/WGDashboard/releases

ARG singbox_version="v1.12.9"
ARG wgdashboard_version="fix-752"

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

WORKDIR $WGDASH

# Copy binaries to container
COPY --from=sing-box /usr/local/bin/sing-box /usr/bin/sing-box
COPY --from=wgdashboard /usr/bin/amneziawg-go /usr/bin/amneziawg-go
COPY --from=wgdashboard /usr/bin/awg /usr/bin/awg
COPY --from=wgdashboard /usr/bin/awg-quick /usr/bin/awg-quick
# Copy app source
COPY --from=wgdashboard /opt/wgdashboard/src .
# Copy scripts and sysctl config to container
COPY ./scripts/ /scripts/
COPY ./entrypoint.sh /entrypoint.sh
COPY ./sysctl.conf /etc/sysctl.conf

# Install dependencies and WGDashboard
RUN set -ex && \
  apk add --no-cache \
  sudo bash curl iptables iproute2 procps tzdata openresolv \
  python3 py3-virtualenv py3-pip py3-psutil py3-bcrypt \
  wireguard-tools openssl jq inotify-tools idn2-utils && \
  mkdir -p /data log download /etc/wireguard /etc/amnezia/amneziawg && \
  rm -rf venv wgd.sh static/app static/client /var/cache/apk/* /root/.cache /root/.local && \
  python3 -m venv ./venv && \
  mv /usr/lib/python3.12/site-packages/psutil* ./venv/lib/python3.12/site-packages && \
  mv /usr/lib/python3.12/site-packages/bcrypt* ./venv/lib/python3.12/site-packages && \
  . ./venv/bin/activate && \
  python3 -m pip install --upgrade pip && \
  python3 -m pip install -r requirements.txt && \
  find / -type d -name '__pycache__' -exec rm -rf {} +  && \
  chmod +x /scripts/* /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD sh -c 'pgrep gunicorn > /dev/null && pgrep tail > /dev/null' || exit 1

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]

