<p align="center">
  <img alt="WGDashboard-sing-box" src="/logo.webp" width="180">
</p>
<h1 align="center">
<a href="https://github.com/donaldzou/WGDashboard">WGDashboard</a> over <a href="https://github.com/SagerNet/sing-box">sing-box</a>
</h1>
<p align="center">
<img alt="Release" src="https://img.shields.io/github/v/release/jinndi/WGDashboard-sing-box">
<img alt="Code size in bytes" src="https://img.shields.io/github/languages/code-size/jinndi/WGDashboard-sing-box">
<img alt="License" src="https://img.shields.io/github/license/jinndi/WGDashboard-sing-box">
<img alt="Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/jinndi/WGDashboard-sing-box/build-wgd.yml">
<img alt="Visitor" src="https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2Fjinndi%2FWGDashboard-sing-box&label=visitor&icon=eye&color=%230d6efd&message=&style=flat&tz=UTC">
</p>

## 🚀 Features

- Proxy for specified CIDR addresses of WireGuard clients
- Optional Cloudflare WARP over direct and proxy connections
- Automatic configuration of forwarding rules for WG interfaces
- Optional AdGuard domain filtering, enabled in just a few clicks.
- Custom DNS (DoH) configuration for both proxy and direct server connections
- Defining Geosite and GeoIP rules to bypass proxy mode
- Specifying domain names that should ignore Geosite and GeoIP proxy bypass rules
- Easy setup of the panel behind a Caddy reverse proxy with auto-renewed SSL certificates
- Plus all other powerful features of the excellent WGDashboard management panel

## 📋 Requirements

- A host with a kernel that supports WireGuard (all modern kernels)
- To use AmneziaWG, you need to install the [kernel module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
- Curl and Docker installed
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

- UDP port(s) (or range of used) of the `wgd` service in `compose.yml`
- `443` TCP/UDP for the `wgd-caddy` service

**You can use the `secure-iptables.sh` script from this repository on Debian/Ubuntu-based systems.**

1. Download with command:

```
curl -fsSLO https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/secure-iptables.sh
```

2. Open script: `nano secure-iptables.sh`

3. Specify all the ports that need to be accessible from outside in the variables `TCP_PORTS` and `UDP_PORTS` for TCP and UDP ports, respectively. The SSH port is detected and allowed automatically, so you do not need to include it.

4. Run the script: `sudo bash secure-iptables.sh`

5. At the end, use `sudo kill <process_number>` to prevent the automatic rollback of the rules after 2 minutes.

> After running the script, you can restore the previous iptables rules with the command: `sudo iptables-restore < /root/iptables.backup && netfilter-persistent save`, to view the current rules: `sudo iptables -L -n -v`

### 5. Run compose.yml

From the same directory where you uploaded and configured compose.yml

```bash
docker compose up -d
```

The panel will be available within 5 minutes after a successful launch at:
`https://WGD_HOST/WGD_PATH`

If you did not configure the wgd-caddy service:
`http://WGD_HOST:WGD_PORT/WGD_PATH`

> Stop: `docker compose down`, Update: `docker compose pull`, Logs: `docker compose logs`

## ⚙️ Options

> [!NOTE]
> If the container(s) are already running, after any changes to the `compose.yml` file, you need to recreate the services using the command `docker compose up -d --force-recreate`.

> [!WARNING]
> WARP-related options will function only if the host does not block the Cloudflare API and the IP addresses required for establishing a WARP connection.

> [!WARNING]
> Domain-based routing rule options (`ENABLE_ADGUARD`, `GEOSITE_BYPASS`, `GEO_NO_DOMAINS`), `hosts` file and the use of server-side DNS specified in `DNS_DIRECT` and `DNS_PROXY` will not work if the WireGuard client configuration does not specify a DNS server and encrypted DNS (DoT, DoH, etc.) is used from the router, browser, or other sources. You can check the DNS you are using, for example, at https://dnsleaktest.com

### _Environment variables of the `wgd` service._

| Env                | Default            | Example                      | Description                                                                                                                                                                                                                                                                  |
| ------------------ | ------------------ | ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TZ`               | `Europe/Amsterdam` | `Europe/Moscow`              | Timezone. Useful for accurate logs and scheduling.                                                                                                                                                                                                                           |
| `WGD_PATH`         | -                  | `secret_path`                | Path to the WEB panel without / in the address bar.                                                                                                                                                                                                                          |
| `WGD_HOST`         | Autodetect IP      | myserver.com                 | Domain or IP for WG clients.                                                                                                                                                                                                                                                 |
| `WGD_PORT`         | `10086`            | `3228`                       | WEB UI port, for Caddy revers proxy.                                                                                                                                                                                                                                         |
| `WGD_LOG_LEVEL`    | `ERROR`            | `INFO`                       | Sets the severity of the logs being displayed. Available: `DEBUG`, `INFO`, `WARNING`, `ERROR` and `CRITICAL`                                                                                                                                                                 |
| `DNS_CLIENTS`      | `1.1.1.1`          | `8.8.8.8`                    | Default DNS for WireGuard clients. Any public DNS address must be specified (the particular one does not matter). This is required for sing-box to intercept it with its own DNS module and apply routing rules with the `DNS_DIRECT` and `DNS_PROXY` addresses (see below). |
| `DNS_DIRECT`       | `77.88.8.8`        | `223.5.5.5`                  | DNS (DoH) for sing-box direct outbaund.                                                                                                                                                                                                                                      |
| `DNS_PROXY`        | `1.1.1.1`          | `9.9.9.9`                    | DNS (DoH) for sing-box proxy outbaund.                                                                                                                                                                                                                                       |
| `ALLOW_FORWARD`    | -                  | `wg0,wg1`                    | By default, all interfaces and peers are isolated from each other. You can specify interface (configuration) names to remove these restrictions.                                                                                                                             |
| `ENABLE_ADGUARD`   | `false`            | `true`                       | Includes a domain blocklist from the project https://github.com/jinndi/adguard-filter-list-srs The list is updated on container startup and only if more than 3 hours have passed since the last update.                                                                     |
| `PROXY_LINK`\*     | -                  | `vless://...` or `ss://...`  | Proxy connection link. If the value is not specified WARP will be used.                                                                                                                                                                                                      |
| `PROXY_CIDR`       | `10.10.10.0/24`    | `10.1.0.0/24,10.2.0.0/24`    | CIDR address list from WireGuard configurations for proxy routing.                                                                                                                                                                                                           |
| `WARP_OVER_PROXY`  | `false`            | `true`                       | If a link is specified in the `PROXY_LINK` setting, setting this parameter to `true` enables the route `WARP → PROXY → Internet`. In this mode, the proxy server’s IP address is hidden behind WARP.                                                                         |
| `WARP_OVER_DIRECT` | `false`            | `true`                       | If set to `true`, direct connections use the Cloudflare WARP proxy. In this mode, the server’s IP address is hidden behind WARP.                                                                                                                                             |
| `GEOSITE_BYPASS`   | -                  | `category-ru,geolocation-cn` | Geosite rules for bypassing proxy by domain names. Use file names from the list (without 'geosite-' prefix): https://github.com/SagerNet/sing-geosite/tree/rule-set                                                                                                          |
| `GEOIP_BYPASS`     | -                  | `ru,by,cn`                   | GeoIP rules for bypassing proxy by country IP addresses. Use file names from the list (without 'geoip-' prefix): https://github.com/SagerNet/sing-geoip/tree/rule-set                                                                                                        |
| `GEO_NO_DOMAINS`   | -                  | `vk.com,habr.com`            | List of domain names that override `GEOSITE_BYPASS` and `GEOIP_BYPASS` rules and are routed through the proxy.                                                                                                                                                               |

\*_`PROXY_LINK` supports_
| Type | Format |
| - | -------------------------------------------------------------------------------------- |
| VLESS over TCP with REALITY and XTLS-RPRX-Vision | `vless://<UUID>@<host>:<port>?security=reality&encryption=none&flow=xtls-rprx-vision&pbk=<base64-encoded-public-key>&sid=<shortID>&sni=<server-name>&fp=<fingerprint>` |
| Shadowsocks-2022 TCP+UDP. Method: 2022-blake3-aes-128-gcm | `ss://<base64-encoded-method:password>@<host>:<port>` (SIP002) or `ss://<method>:<password>@<host>:<port>` |

You can use the `xray-install.sh` script from this repository on Debian/Ubuntu-based systems.

It is quite convenient: it allows you to deploy an XRay server on another machine and obtain all available links for `PROXY_LINK`.

The script installs XRay into `/opt/xray`, and you can manage it using the `xray` command.

Install it with the following command:

```
curl -fsSLO https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/xray-install.sh \
&& sudo bash xray-install.sh
```

### _Environment variables of the `wgd-caddy` service._

| Env            | Default | Example         | Description                                                                   |
| -------------- | ------- | --------------- | ----------------------------------------------------------------------------- |
| `DOMAIN`       | -       | `my.domain.com` | Required. Domain linked to your server's IP.                                  |
| `EMAIL`        | -       | `my@email.com`  | Required. Your email adress, used when creating an ACME account with your CA. |
| `SERVICE_NAME` | `wgd`   | `wgdashboard`   | Corresponds to service name WGDashboard (For revers proxy).                   |
| `SERVICE_PORT` | `10086` | `13228`         | Corresponds to WGD_PORT (For revers proxy).                                   |

## 🌐 Hosts

You can mount your own hosts file to the wgd service, for example, to block unwanted domains.

> [!WARNING]
> This will not work for clients connecting with encrypted DNS (DoT/DoH)

For this purpose, check out **StevenBlack [hosts](https://github.com/StevenBlack/hosts)** project.

### 1. Create the hosts file

```
touch "$HOME/hosts"
docker run --pull always --rm -it -v "$HOME/hosts:/etc/hosts" \
ghcr.io/stevenblack/hosts:latest updateHostsFile.py --auto \
--replace --compress --extensions gambling fakenews
```

- This command generates a ready-to-use hosts file.

- In addition to the general adware/malware lists, it blocks **gambling** and **fakenews** domains.

- Mount it to the `wgd` container:

```
    volumes:
      ...
      - "$HOME/hosts:/opt/hosts:ro"
```

### 2. Automate updates with cron

To keep your hosts file up-to-date and optionally reboot the server:

1. Open root crontab:

```
sudo crontab -e
```

2. Add the following cron job (runs daily at 4:30 AM):

```
30 4 * * * docker run --pull always --rm -v "/absolute/path/to/hosts:/etc/hosts" ghcr.io/stevenblack/hosts:latest updateHostsFile.py --auto --replace --compress --extensions gambling fakenews && /sbin/reboot
```

- Replace `/absolute/path/to/hosts` with the absolute path to your hosts file.

- The command updates the hosts file and reboots the server automatically.
