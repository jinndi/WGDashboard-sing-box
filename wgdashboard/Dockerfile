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
FROM debian:trixie-slim
LABEL maintainer="Jinndi <alncores@gmail.com>"

# Environment variables
ENV SINGBOX_TUN_NAME=singbox \
    WGDASH=/opt/wgdash \
    PATH=/root/.local/bin:$PATH

# Install dependencies
RUN apt update && apt install -y \
  sudo bash curl iptables iproute2 \
  procps tzdata openresolv openrc \
  build-essential python3-dev libssl-dev  \
  openssl jq inotify-tools

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

# Install WGDashboard
RUN set -ex && \
  mkdir -p /data log download /etc/wireguard /etc/amnezia/amneziawg && \
  rm -rf venv static/app static/client && \
  curl -Lf https://astral.sh/uv/install.sh | sh && \
  uv python install && uv venv && \
  . .venv/bin/activate && uv pip install -r requirements.txt && \
  rm -rf /var/lib/apt/lists/* /root/.cache /configs /root/.local && \
  find ./ -type f -name '*.pyc' -delete && find ./ -type d -name '__pycache__' -delete && \
  chmod +x /scripts/* /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD sh -c 'pgrep gunicorn > /dev/null && pgrep tail > /dev/null' || exit 1

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]

