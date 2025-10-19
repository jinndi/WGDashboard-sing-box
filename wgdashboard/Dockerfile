# Release links:
# https://github.com/SagerNet/sing-box/releases
# https://github.com/WGDashboard/WGDashboard/releases

FROM ghcr.io/sagernet/sing-box:v1.12.10 AS sing-box

FROM ghcr.io/wgdashboard/wgdashboard:v4.3.1-dev AS wgdashboard

# Build stage
FROM alpine:3.22 AS builder

WORKDIR /

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY --from=wgdashboard /opt/wgdashboard/src/requirements.txt .

RUN apk add --no-cache \
    python3 \
    py3-pip \
    build-base \
    pkgconfig \
    python3-dev \
    libffi-dev \
    linux-headers \
    rust \
    cargo
RUN python3 -m venv /python && \
    . /python/bin/activate && \
    pip3 install -U pip && \
    pip3 install -r requirements.txt

# Final stage
FROM alpine:3.22

LABEL org.opencontainers.image.version=4.3.0.1
LABEL org.opencontainers.image.title=WGDashboard-sing-box
LABEL org.opencontainers.image.description="WGDashboard over Sing-Box"
LABEL org.opencontainers.image.documentation=https://github.com/jinndi/WGDashboard-sing-box
LABEL maintainer=Jinndi

ENV SINGBOX_TUN_NAME=singbox
ENV WGDASH=/app
ENV PATH=/python/bin:${PATH}

WORKDIR $WGDASH

COPY --from=builder /python /python
COPY --from=sing-box /usr/local/bin/sing-box /usr/bin/sing-box
COPY --from=wgdashboard \
      /usr/bin/amneziawg-go \
      /usr/bin/awg \
      /usr/bin/awg-quick \
      /usr/bin/
COPY --from=wgdashboard /opt/wgdashboard/src .
COPY ./scripts/ /scripts/
COPY ./entrypoint.sh /entrypoint.sh
COPY ./sysctl.conf /etc/sysctl.conf

RUN set -ex && \
    apk add --no-cache \
      bash curl iptables iproute2 procps tzdata \
      python3 wireguard-tools \
      openssl jq inotify-tools idn2-utils
RUN rm -rf venv wgd.sh test.sh static/app static/client \
      requirements.txt certbot.ini wg-dashboard.service && \
    mkdir -p /data log download /etc/wireguard /etc/amnezia/amneziawg
RUN python3 -OO -m compileall $WGDASH
RUN chmod -R +x /scripts /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
