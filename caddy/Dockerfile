# Release links:
# https://hub.docker.com/_/caddy

# Versions of images
ARG caddy_version="2.10-alpine"

# Caddy base image
FROM docker.io/library/caddy:${caddy_version}
LABEL maintainer="Jinndi <alncores@gmail.com>"

# Add bash
RUN apk add --no-cache bash

# Copy scripts to container
COPY ./entrypoint.sh /entrypoint.sh

# Making scripts executable
RUN chmod +x /entrypoint.sh

# Launch entrypoint
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]

# Launch caddy
CMD ["/usr/bin/caddy", "run", "-c", "/etc/caddy/Caddyfile", "-a", "caddyfile"]