# Release links:
# https://github.com/SagerNet/sing-box/releases
# https://github.com/donaldzou/WGDashboard/releases

ARG singbox_version="v1.12.5"
ARG wgdashboard_version="v4.2.5"

# Building sing-box to copy the binary
FROM ghcr.io/sagernet/sing-box:${singbox_version} AS sing-box

# Building WGDashboard base image
FROM ghcr.io/donaldzou/wgdashboard:${wgdashboard_version}
LABEL maintainer="Jinndi <alncores@gmail.com>"

# The name for the tun interface is sing-box
ENV SINGBOX_TUN_NAME=singbox

# Copy sing-box binary
COPY --from=sing-box /usr/local/bin/sing-box /bin/sing-box
# Copy scripts and sysctl config to container
COPY ./scripts/ /scripts/
COPY ./entrypoint.sh /entrypoint.sh
COPY ./sysctl.conf /etc/sysctl.conf

# Install openssl jq inotify-tools, remove unzip
RUN apk add --no-cache openssl jq inotify-tools; \
  apk del unzip

# Install Python dependencies && WGDashboard
RUN /bin/bash -c "python3 -m venv ${WGDASH}/src/venv && source ${WGDASH}/src/venv/bin/activate \
  && mv /usr/lib/python3.12/site-packages/psutil* ${WGDASH}/src/venv/lib/python3.12/site-packages \
  && mv /usr/lib/python3.12/site-packages/bcrypt* ${WGDASH}/src/venv/lib/python3.12/site-packages \
  && mkdir -p /etc/wireguard/WGDashboard_Backup /etc/amnezia/amneziawg/WGDashboard_Backup \
  && cd ${WGDASH}/src && chmod +x ${WGDASH}/src/wgd.sh && ${WGDASH}/src/wgd.sh install \
  && mv ${WGDASH}/src/static/app/dist /dist_temp && rm -rf ${WGDASH}/src/static/app/* \
  && mv /dist_temp ${WGDASH}/src/static/app/dist \
  && rm -rf ${WGDASH}/src/db /var/cache/apk/* /root/.cache /configs /root/.local \
  && find / -type f -name '*.pyc' -delete && find / -type d -name '__pycache__' -delete \
  && rm -f ${WGDASH}/src/wg-dashboard.ini  && chmod +x /entrypoint.sh \
  && find /scripts -type f -exec chmod +x {} \;"

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
