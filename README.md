# WGDashboard-sing-box

**[WGDashboard](https://github.com/donaldzou/WGDashboard) running on top of [sing-box](https://github.com/SagerNet/sing-box)**


## 🚀 Features
- Ability to specify a CIDR in the WireGuard configuration through which the proxy will operate
- Proxy connection via a supported protocol link
- Blocking of advertising domains using Geosite (category-ads-all) by default
- Custom DNS (DoH) configuration for both proxy and direct server connections
- Defining Geosite and GeoIP rules to bypass proxy mode
- Specifying domain names that should ignore Geosite and GeoIP proxy bypass rules
- Easy setup of the panel behind a Caddy reverse proxy with auto-renewed SSL certificates
- Plus all other powerful features of the excellent WGDashboard management panel

## ⚠️ Requirements
- A host with a kernel that supports WireGuard (all modern kernels).
- A host with curl and Docker installed.
- You need to have a domain name or a public IP address


## 🐳 Installation

### 1. Install Docker

If you haven't installed Docker yet, install it by running

```bash
curl -sSL https://get.docker.com | sh
sudo usermod -aG docker $(whoami)
```

### 2. Download docker compose file in curren dirrectory

```bash
sudo curl -O https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/compose.yml
```

### 3. Fill in the environment variables using any convenient editor, for example nano

```bash
nano compose.yml
```

### 4. Setup Firewall
If you are using a firewall, you need to open the following ports:
-  UDP port(s) of the `wgd` service in `compose.yml`
- `443` for the `wgd-caddy` service

### 5. Run compose.yml

From the same directory where you uploaded and configured compose.yml

```bash
sudo docker compose up -d
```

The panel will be available within 5 minutes after a successful launch at:
`https://WGD_HOST/WGD_PATH`

If you did not configure the wgd-caddy service:
`http://WGD_HOST:WGD_PORT/WGD_PATH`


## ⚙️ Options

### *Environment variables of the `wgd` service.*

| Env | Default | Example | Description |
| - | - | - | -------------------------------------------------------------------------------------- |
| `TZ` | `Europe/Amsterdam` | `Europe/Moscow` | Timezone. Useful for accurate logs and scheduling. |
| `WGD_PATH` | - | `secret_path` | Path to the WEB panel without / in the address bar. |
| `WGD_HOST` | Autodetect IP | myserver.com | Domain or IP for WG clients. |
| `WGD_PORT` | `10086` | `3228` | WEB UI port, for Caddy revers proxy. |
| `DNS_CLIENTS` | `1.1.1.1` | `8.8.8.8` | Default DNS for WireGuard clients. |
| `DNS_DIRECT` | `77.88.8.8` | `213.158.0.6` | DNS (DoH) for sing-box  direct outbaund. |
| `DNS_PROXY`| `1.1.1.1` | `9.9.9.9` | DNS (DoH) for sing-box proxy outbaund. |
| `PROXY_LINK`* | - | `vless://...` or `ss://...` | Proxy connection link. |
| `CIDR_PROXY` | `10.10.10.0/24` | `10.1.0.0/24,10.2.0.0/24` | CIDR address list from WireGuard configurations for proxy routing. |
| `GEOSITE_BYPASS` | - | `category-ru,geolocation-cn` | Geosite rules for bypassing proxy by domain names. Use file names from the list (without 'geoip-' prefix): https://github.com/SagerNet/sing-geosite/tree/rule-set |
| `GEOIP_BYPASS` | - | `ru,by,cn` | GeoIP rules for bypassing proxy by country IP addresses. Use file names from the list (without 'geoip-' prefix): https://github.com/SagerNet/sing-geoip/tree/rule-set |
| `GEO_NO_DOMAINS` | - | `vk.com,habr.com` | List of domain names that override `GEOSITE_BYPASS` and `GEOIP_BYPASS` rules and are routed through the proxy. |

**`PROXY_LINK` supports*
| Type | Format |
| - | -------------------------------------------------------------------------------------- |
| VLESS over TCP with REALITY and XTLS-RPRX-Vision | `vless://<UUID>@<host>:<port>?security=reality&encryption=none&flow=xtls-rprx-vision&pbk=<base64-encoded-public-key>&sid=<shortID>&sni=<server-name>&fp=<fingerprint>` |
| Shadowsocks-2022 over TCP. Method: 2022-blake3-aes-128-gcm | `ss://<base64-encoded-method:password>@<host>:<port>(?network=tcp,...)?` or `ss://method:password@<host>:<port>(?network=tcp,...)?` |

You can use the `xray-install.sh` script from this repository on Debian 10+ or ​​Ubuntu 18.04+
It is quite convenient: it allows you to deploy an XRay server on another machine and obtain all available links for `PROXY_LINK`.  

The script installs XRay into `/opt/xray`, and you can manage it using the `xray` command.  

Install it with the following command:

```
curl -fsSLO "https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/xray-install.sh" \
&& bash xray-install.sh
```

### *Environment variables of the `wgd-caddy` service.*

| Env | Default | Example | Description |
| - | - | - | -------------------------------------------------------------------------------------- |
| `DOMAIN` | - | `my.domain.com` | Required. Domain linked to your server's IP. |
| `EMAIL` | - | `my@email.com` | Required. Your email adress, used when creating an ACME account with your CA. |
| `SERVICE_NAME` | `wgd` | `wgdashboard` | Corresponds to service name WGDashboard (For revers proxy). |
| `SERVICE_PORT` | `10086` | `13228` | Corresponds to WGD_PORT (For revers proxy). |
