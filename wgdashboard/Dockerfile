# https://github.com/SagerNet/sing-box/releases
ARG v_singbox="v1.12.13"
# https://github.com/WGDashboard/WGDashboard/releases
ARG v_wgdash="v4.3.1"
# https://hub.docker.com/_/alpine/tags
ARG v_alpine="3.22"

FROM ghcr.io/sagernet/sing-box:${v_singbox} AS sing-box

FROM ghcr.io/wgdashboard/wgdashboard:${v_wgdash} AS wgdashboard

# Build stage
FROM alpine:${v_alpine} AS builder

ENV WDIR=/app
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR $WDIR

COPY --from=sing-box \
      /usr/local/bin/sing-box \
      /bins/sing-box
COPY --from=wgdashboard \
      /usr/bin/amneziawg-go \
      /usr/bin/awg \
      /usr/bin/awg-quick \
      /bins/
COPY --from=wgdashboard /opt/wgdashboard/src .

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
RUN rm -rf \
      venv \
      wgd.sh \
      test.sh \
      static/app \
      static/client \
      certbot.ini \
      wg-dashboard.service
RUN mkdir -p log download
RUN python3 -OO -m compileall $WDIR
RUN python3 -m venv /py && \
    . /py/bin/activate && \
    pip3 install -U pip && \
    pip3 install -r requirements.txt
RUN rm -rf requirements.txt
# Replacement of paths with relative ones for namespace handling when using a reverse proxy
RUN set -ex && \
  find static/dist -type f \( -name "*.html" -o -name "*.js" \) \
    -exec sed -i 's|/static/dist|./static/dist|g' {} \; && \
  find static/dist -type f -name "*.css" \
    -exec sed -i \
    -e 's|/static/dist/WGDashboardAdmin/assets/|./|g' \
    -e 's|/static/dist/WGDashboardAdmin/img/|../img/|g' \
    -e 's|/static/dist/WGDashboardClient/assets/|./|g' \
    -e 's|/static/dist/WGDashboardClient/img/|../img/|g' {} \;

# Final stage
FROM alpine:${v_alpine}

LABEL org.opencontainers.image.version=4.3.1
LABEL org.opencontainers.image.title=WGDashboard-sing-box
LABEL org.opencontainers.image.description="WGDashboard over Sing-Box"
LABEL org.opencontainers.image.documentation=https://github.com/jinndi/WGDashboard-sing-box
LABEL maintainer=Jinndi

ENV SINGBOX_TUN_NAME=singbox
ENV WGDASH=/app
ENV PATH=/py/bin:/bin:${PATH}

WORKDIR $WGDASH

COPY --from=builder /app /app
COPY --from=builder /py /py
COPY --from=builder /bins /bin
COPY ./scripts/ /scripts/
COPY ./entrypoint.sh /entrypoint.sh
COPY ./sysctl.conf /etc/sysctl.conf

RUN set -ex && \
    apk add --no-cache \
      bash curl iptables iproute2 procps tzdata \
      python3 wireguard-tools \
      openssl jq inotify-tools idn2-utils
RUN mkdir -p /data /etc/wireguard /etc/amnezia/amneziawg && \
    chmod -R +x /scripts /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
