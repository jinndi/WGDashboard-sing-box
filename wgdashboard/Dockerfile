# Release links:
# https://hub.docker.com/_/golang/
# https://github.com/SagerNet/sing-box/releases
# https://github.com/donaldzou/WGDashboard/releases


# Versions of images
ARG golang_version="1.24"
ARG singbox_version="v1.12.1"


# Building awg-go to copy the binary
FROM golang:${golang_version} AS awg-go
RUN git clone https://github.com/WGDashboard/amneziawg-go /awg
WORKDIR /awg
RUN go mod download && \
    go mod verify && \
    go build -ldflags '-linkmode external -extldflags "-fno-PIC -static"' -v -o /usr/bin


# Building awg-tools to copy the binary
FROM alpine:latest AS awg-tools
RUN apk update && apk add --no-cache \
    make git build-base linux-headers \
  && git clone https://github.com/WGDashboard/amneziawg-tools \
  && cd amneziawg-tools/src \
  && make \
  && chmod +x wg*


# Building sing-box to copy the binary
FROM ghcr.io/sagernet/sing-box:${singbox_version} AS sing-box


# Building WGDashboard base image
FROM alpine:latest
LABEL maintainer="Jinndi <alncores@gmail.com>"

# WGDashboard path
ENV WGDASH=/opt/wgd

RUN apk update && apk add --no-cache \
    iproute2 iptables bash curl wget unzip procps sudo \
    tzdata wireguard-tools python3 py3-psutil py3-bcrypt openresolv


# Installing Packages and creating folders
RUN apk update && apk upgrade && apk add --no-cache \
    iproute2 iptables bash curl wget unzip procps sudo \
    tzdata wireguard-tools python3 py3-pip py3-virtualenv  \
    openresolv gcc python3-dev musl-dev linux-headers py3-psutil py3-bcrypt \
    && mv /usr/lib/python3.12/site-packages/psutil* ${WGDASH}/venv/lib/python3.12/site-packages \
    && mv /usr/lib/python3.12/site-packages/bcrypt* ${WGDASH}/venv/lib/python3.12/site-packages \
    && mkdir /data \
    && mkdir -p ${WGDASH} \
    && mkdir -p /etc/amnezia/amneziawg

# Copy binary from another stage
COPY --from=awg-go /usr/bin/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-tools /amneziawg-tools/src/wg /usr/bin/awg
COPY --from=awg-tools /amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
COPY --from=sing-box /usr/local/bin/sing-box /usr/bin/sing-box

# Copy souce WGDashboard files
COPY ./source/src ${WGDASH}

# Install Python dependencies && WGDashboard
RUN /bin/bash -c "python3 -m venv ${WGDASH}/venv \
  && source ${WGDASH}/venv/bin/activate \
  && pip3 install --no-cache-dir -r ${WGDASH}/requirements.txt \
  && chmod +x ${WGDASH}/wgd.sh \
  && ${WGDASH}/wgd.sh install \
  && rm -rf ${WGDASH}/db \
  && rm -f ${WGDASH}/wg-dashboard.ini"

# Copy scripts and sysctl config to container
COPY ./vless-parse.sh ./entrypoint.sh /
COPY ./sysctl.conf /etc/sysctl.conf

# Making scripts executable
RUN chmod +x /vless-parse.sh /entrypoint.sh

# Defining a way for Docker to check the health of the container.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD sh -c 'pgrep gunicorn > /dev/null && pgrep tail > /dev/null' || exit 1

# Exposing the default WireGuard Dashboard port for web access.
EXPOSE 10086

WORKDIR $WGDASH

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]