# WGDashboard-sing-box

[WGDashboard](https://github.com/donaldzou/WGDashboard) running on top of [sing-box](https://github.com/SagerNet/sing-box)

## Features
- Ability to specify a CIDR in the WireGuard configuration through which the proxy will operate
- Proxy connection via a supported protocol link
- Blocking of advertising domains using Geosite (category-ads-all) by default
- Custom DNS (DoH) configuration for both proxy and direct server connections
- Defining Geosite and GeoIP rules to bypass proxy mode
- Specifying domain names that should ignore Geosite and GeoIP proxy bypass rules
- Easy setup of the panel behind a Caddy reverse proxy with auto-renewed SSL certificates
- Plus all other powerful features of the excellent WGDashboard management panel

## Requirements
- A host with a kernel that supports WireGuard (all modern kernels).
- A host with curl and Docker installed.
- You need to have a domain name or a public IP address

## Installation

### 1. Install Docker

If you haven't installed Docker yet, install it by running

```bash
curl -sSL https://get.docker.com | sh
sudo usermod -aG docker $(whoami)
```

### 2. Download docker compose file in curren dirrectory

```bash
sudo curl -O https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/docker-compose.yml
```

### 3. Fill in the environment variables using any convenient editor, for example nano

```bash
nano docker-compose.yml
```

### 4. Setup Firewall
If you are using a firewall, you need to open the following ports:
-  UDP port(s) of the `wgd` service in `docker-compose.yml`
- `443` for the `wgd-caddy` service

### 5. Run docker-compose.yml

From the same directory where you uploaded and configured docker-compose.yml

```bash
sudo docker compose up -d
```

The panel will be available within 5 minutes after a successful launch at:
`https://WGD_HOST/WGD_PATH`

If you did not configure the wgd-caddy service:
`http://WGD_HOST:WGD_PORT/WGD_PATH`

## Options

