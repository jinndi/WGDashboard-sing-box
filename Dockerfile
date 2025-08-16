# Release links:
# https://github.com/SagerNet/sing-box/releases
# https://github.com/donaldzou/WGDashboard/releases

# Versions of images
ARG singbox_version="v1.12.1"
ARG wgdashboard_version="v4.2.5"

# Building sing-box to copy the binary
FROM ghcr.io/sagernet/sing-box:${singbox_version} AS sing-box

# WGDashboard base image
FROM docker.io/donaldzou/wgdashboard:${wgdashboard_version}

# Copy the sing-box binary from another stage
COPY --from=sing-box /usr/local/bin/sing-box /bin/sing-box

# Copy scripts and sysctl config to container
COPY ./vless-parse.sh ./entrypoint.sh /
COPY ./sysctl.conf /etc/sysctl.conf

# Making scripts executable
RUN chmod +x /vless-parse.sh /entrypoint.sh

# Launch entrypoint
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]