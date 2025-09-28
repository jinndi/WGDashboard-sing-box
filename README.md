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

### 5. Run compose.yml

From the same directory where you uploaded and configured compose.yml

```bash
docker compose up -d
```

The panel will be available within 5 minutes after a successful launch at:
`https://WGD_HOST/<path>`

If you did not configure the wgd-caddy service:
`http://WGD_HOST:WGD_PORT`

> Stop: `docker compose down`, Update: `docker compose pull`, Logs: `docker compose logs`

## ⚙️ Options

> [!NOTE]
> If the container(s) are already running, after any changes to the `compose.yml` file, you need to recreate the services using the command `docker compose up -d --force-recreate`.

> [!WARNING]
> WARP-related options will function only if the host does not block the Cloudflare API and the IP addresses required for establishing a WARP connection.

> [!WARNING]
> Domain-based routing rule options (`ENABLE_ADGUARD`, `GEOSITE_BYPASS`, `GEO_NO_DOMAINS`), `hosts` file and the use of server-side DNS specified in `DNS_DIRECT` and `DNS_PROXY` will not work if the WireGuard client configuration does not specify a DNS server and encrypted DNS (DoT, DoH, etc.) is used from the router, browser, or other sources. You can check the DNS you are using, for example, at https://dnsleaktest.com

### _Environment variables of the `wgd` service._

| Env                | Default            | Example                                     | Description                                                                                                                                                                                                                                                                  |
| ------------------ | ------------------ | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TZ`               | `Europe/Amsterdam` | `Europe/Moscow`                             | Timezone. Useful for accurate logs and scheduling.                                                                                                                                                                                                                           |
| `WGD_HOST`         | Autodetect IP      | `myserver.com`                              | Domain or IP for WG clients.                                                                                                                                                                                                                                                 |
| `WGD_PORT`         | `10086`            | `3228`                                      | WEB UI port.                                                                                                                                                                                                                                                                 |
| `DNS_CLIENTS`      | `1.1.1.1`          | `8.8.8.8`                                   | Default DNS for WireGuard clients. Any public DNS address must be specified (the particular one does not matter). This is required for sing-box to intercept it with its own DNS module and apply routing rules with the `DNS_DIRECT` and `DNS_PROXY` addresses (see below). |
| `DNS_DIRECT`       | `77.88.8.8`        | `223.5.5.5`                                 | DNS (DoH) for sing-box direct outbaund.                                                                                                                                                                                                                                      |
| `DNS_PROXY`        | `1.1.1.1`          | `9.9.9.9`                                   | DNS (DoH) for sing-box proxy outbaund.                                                                                                                                                                                                                                       |
| `ALLOW_FORWARD`    | -                  | `wg0,wg1`                                   | By default, all interfaces and peers are isolated from each other. You can specify interface (configuration) names to remove these restrictions.                                                                                                                             |
| `ENABLE_ADGUARD`   | `false`            | `true`                                      | Includes a domain blocklist from the project https://github.com/jinndi/adguard-filter-list-srs The list is updated on container startup and only if more than 3 hours have passed since the last update.                                                                     |
| `PROXY_LINK`\*     | -                  | `vless://...`, `ss://...` or `socks5://...` | Proxy connection link. If the value is not specified WARP will be used.                                                                                                                                                                                                      |
| `PROXY_CIDR`       | `10.10.10.0/24`    | `10.1.0.0/24,10.2.0.0/24`                   | CIDR address list from WireGuard configurations for proxy routing.                                                                                                                                                                                                           |
| `WARP_OVER_PROXY`  | `false`            | `true`                                      | If a link is specified in the `PROXY_LINK` setting, setting this parameter to `true` enables the route `WARP → PROXY → Internet`. In this mode, the proxy server’s IP address is hidden behind WARP.                                                                         |
| `WARP_OVER_DIRECT` | `false`            | `true`                                      | If set to `true`, direct connections use the Cloudflare WARP proxy. In this mode, the server’s IP address is hidden behind WARP.                                                                                                                                             |
| `GEOSITE_BYPASS`   | -                  | `category-ru,geolocation-cn`                | Geosite rules for bypassing proxy by domain names. Use file names from the list (without 'geosite-' prefix): https://github.com/SagerNet/sing-geosite/tree/rule-set                                                                                                          |
| `GEOIP_BYPASS`     | -                  | `ru,by,cn`                                  | GeoIP rules for bypassing proxy by country IP addresses. Use file names from the list (without 'geoip-' prefix): https://github.com/SagerNet/sing-geoip/tree/rule-set                                                                                                        |
| `GEO_NO_DOMAINS`   | -                  | `vk.com,habr.com`                           | List of domain names that override `GEOSITE_BYPASS` and `GEOIP_BYPASS` rules and are routed through the proxy.                                                                                                                                                               |
| `LOG_LEVEL`        | `fatal`            | `info`                                      | Log Level. One of: `trace` `debug` `info` `warn` `error` `fatal` `panic`                                                                                                                                                                                                     |

\*_`PROXY_LINK` supports_
| Type | Format |
| - | -------------------------------------------------------------------------------------- |
| [`WARP`](https://one.one.one.one/) ([`wireguard`](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)) | By default, if `PROXY_LINK` is not set |
| [`VLESS`](https://sing-box.sagernet.org/configuration/outbound/vless/): `REALITY+Vision` | `vless://<UUID>@<host>:<port>?security=reality&encryption=none&flow=xtls-rprx-vision&pbk=<base64-encoded-public-key>&sid=<shortID>&sni=<server-name>&fp=<fingerprint>` |
| [`Shadowsocks-2022`](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/): `2022-blake3-aes-128-gcm`, [`multiplex`](https://sing-box.sagernet.org/manual/proxy-protocol/shadowsocks/) (h2mux). | `ss://<base64-encoded-method:password>@<host>:<port>` (SIP002) or `ss://<method>:<password>@<host>:<port>` |
| [`Socks5`](https://sing-box.sagernet.org/configuration/inbound/socks/): [`UDP over TCP`](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/). | `socks5://<user>:<password>@<host>:<port>` or `socks5://<host>:<port>` |

### _Environment variables of the `wgd-caddy` service._

> [!WARNING]
> After setting up the reverse proxy, edit your compose.yml file and remove the ports mapping from the corresponding service.

| Env                  | Default               | Example                                    | Description                                                                                                                                                                                                                                   |
| -------------------- | --------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DOMAIN`             | -                     | `my.domain.com`                            | Required. Domain linked to your server's IP.                                                                                                                                                                                                  |
| `EMAIL`              | -                     | `my@email.com`                             | Required. Your email adress, used when creating an ACME account with your CA.                                                                                                                                                                 |
| `PROXY`              | -                     | `3xui:2053/dashboard,other.com/dashboard2` | Addresses for the reverse proxy. You can add multiple values separated by commas. Each value must follow the format `<domain_or_ip>:<port>/<prefix>` or `<domain_or_ip>/<prefix>`. The **prefix will be passed** to the proxy backend itself. |
| `PROXY_STRIP_PREFIX` | `wgd:10086/dashboard` | `wgd:10086/dashboard,other.com/dashboard2` | Same as `PROXY`, except the **prefix will not be passed** to the proxy backend.                                                                                                                                                               |
| `LOG_LEVEL`          | `info`                | `error`                                    | Log Level. Possible values: `debug`, `info`, `warn`, `error`, and very rarely, `panic`, `fatal`                                                                                                                                               |

## 🔍 More Info

<details>
<summary>How to open ports with iptables?</summary>
<hr>

You can use the `secure-iptables.sh` script from this repository on Debian/Ubuntu-based systems:

1. Download with command:

```
curl -fsSLO https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/scripts/secure-iptables.sh
```

2. Open script: `nano secure-iptables.sh`

3. Specify all the ports that need to be accessible from outside in the variables `TCP_PORTS` and `UDP_PORTS` for TCP and UDP ports, respectively. The SSH port is detected and allowed automatically, so you do not need to include it.

4. Run the script: `sudo bash secure-iptables.sh`

5. At the end, use `sudo kill <process_number>` to prevent the automatic rollback of the rules after 2 minutes.

> After running the script, you can restore the previous iptables rules with the command: `sudo iptables-restore < /root/iptables.backup && netfilter-persistent save`, to view the current rules: `sudo iptables -L -n -v`

<hr>
</details>

<details>
<summary>How to get a connection link for the proxy?</summary>
<hr>

You can use the `sing-box-server-install.sh` script from this repository on Debian/Ubuntu-based systems:

It is quite convenient: it allows you to deploy on another machine and obtain all available links for `PROXY_LINK`.

The script installs into `/opt/sing-box`, and you can control them using the `sing-box` command.

Install it with the following command:

```
curl -fsSLO https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/scripts/sing-box-server-install.sh \
&& sudo bash sing-box-server-install.sh
```

<hr>
</details>

<details>
<summary>How to use the 3x-ui panel with WGDashboard proxy on the same host?</summary>
<hr>

If you want to manage the proxy via the 3x-ui panel on the same host as WGDashboard:

- Add the following to your `services` section:

```
  3xui:
    image: ghcr.io/mhsanaei/3x-ui:latest
    container_name: 3xui
    restart: unless-stopped
    volumes:
      - $PWD/db/:/etc/x-ui/
      - $PWD/cert/:/root/cert/
    environment:
      XRAY_VMESS_AEAD_FORCED: "false"
      XUI_ENABLE_FAIL2BAN: "true"
    ports:
      - 2053:2053/tcp
    tty: true
    networks:
      - wgd_net
```

- In the 3x-ui web interface, create an inbound of type `mixed` without a password, for example using port `10800`

- Set the `PROXY_LINK` to: `socks5://3xui:10800`

- If you are using Caddy (`wgd-caddy` service), first in the settings panel, specify the path to the panel itself, and set the `PROXY` variable in its service, for example: `3xui:2053/<your-path>`.

- Finally, configure outbounds and routing in 3x-ui according to your needs

<hr>
</details>

<details>
<summary>How to use the hosts file?</summary>
<hr>

You can mount your own hosts file to the wgd service, for example, to block unwanted domains.

> ! This will not work for clients connecting with encrypted DNS (DoT/DoH)

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

<hr>
</details>
