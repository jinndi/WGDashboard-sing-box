# Release links:
# https://github.com/SagerNet/sing-box/releases
# https://github.com/donaldzou/WGDashboard/releases

ARG singbox_version="v1.12.1"
ARG wgdashboard_version="v4.2.5"

# Building sing-box to copy the binary
FROM ghcr.io/sagernet/sing-box:${singbox_version} AS sing-box

# Building WGDashboard base image
FROM ghcr.io/donaldzou/wgdashboard:${wgdashboard_version}
LABEL maintainer="Jinndi <alncores@gmail.com>"

# Copy sing-box binary 
COPY --from=sing-box /usr/local/bin/sing-box /bin/sing-box

# Install Python dependencies && WGDashboard
RUN /bin/bash -c "python3 -m venv ${WGDASH}/src/venv \
  && source ${WGDASH}/src/venv/bin/activate \
  && mv /usr/lib/python3.12/site-packages/psutil* ${WGDASH}/src/venv/lib/python3.12/site-packages \
  && mv /usr/lib/python3.12/site-packages/bcrypt* ${WGDASH}/src/venv/lib/python3.12/site-packages \
  && cd ${WGDASH}/src && chmod +x ${WGDASH}/src/wgd.sh \
  && ${WGDASH}/src/wgd.sh install \
  && rm -rf ${WGDASH}/src/db ${WGDASH}/src/log \
  && rm -f ${WGDASH}/src/wg-dashboard.ini"

# Copy scripts and sysctl config to container
COPY ./vless-parse.sh ./entrypoint.sh /
COPY ./sysctl.conf /etc/sysctl.conf

# Making scripts executable
RUN chmod +x /vless-parse.sh /entrypoint.sh

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]