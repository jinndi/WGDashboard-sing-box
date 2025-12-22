<p align="center">
  <img alt="WGDashboard-sing-box" src="/logo.webp" width="180">
</p>
<h1 align="center">
<a href="https://github.com/jinndi/WGDashboard">WGDashboard</a> over <a href="https://github.com/jinndi/sing-box">sing-box</a>
</h1>
<p align="center">
<img alt="License" src="https://img.shields.io/github/license/jinndi/WGDashboard-sing-box">
<img alt="Visitor" src="https://hitscounter.dev/api/hit?url=https%3A%2F%2Fgithub.com%2Fjinndi%2FWGDashboard-sing-box&label=visitor&icon=eye&color=%230d6efd&message=&style=flat&tz=UTC">
</p>

## 🚀 Features

- Creating a proxy connection over multiple protocols
- Routing based on GeoSite and GeoIP lists
- Routing only for specified CIDR addresses of WireGuard configurations
- Automatic configuration of forwarding rules for WG interfaces
- Custom DNS configuration for both proxy and direct server connections
- AdGuard domain filtering, enabled in just a few clicks
- Blocking using domain prefixes, GeoSite, and GeoIP lists
- Cloudflare WARP over direct and proxy connections
- [Caddy reverse proxy](https://github.com/jinndi/caddy) with auto-renewed SSL certificates

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
curl -O https://raw.githubusercontent.com/jinndi/WGDashboard-sing-box/main/compose.yml
```

### 3. Fill in the environment variables using any convenient editor, for example nano

```bash
nano compose.yml
```

### 4. Setup Firewall

If you are using a firewall, you need to open ports of the `sb` service in `compose.yml`

### 5. Run compose.yml

From the same directory where you uploaded and configured compose.yml

```bash
docker compose up -d
```

The panel launch at:
`https://<HOST>/<path>/`

If you did not configure the caddy service:
`http://<HOST>:<PORT>`

> Stop: `docker compose down`, Update: `docker compose pull`, Logs: `docker compose logs`

## ⚙️ Options

> [!NOTE]
> If the container(s) are already running, after any changes to the `compose.yml` file, you need to recreate the services using the command `docker compose up -d --force-recreate`.

> [!NOTE]
> If you are using encrypted DNS (DoT, DoH, etc.) on your router, in your browser, or from another source, then on https://dnsleaktest.com you will see that this encrypted DNS is being used. Otherwise, you will see the DNS servers defined in the `DNS_CLIENTS` and `DNS_DIRECT` options for direct routing and proxy respectively. In both cases, domain-based routing will work correctly.

> [!WARNING]
> WARP-related options will function only if the host does not block the Cloudflare API and the IP addresses required for establishing a WARP connection.

### _Environment variables of the `wgd` service._

| Env                | Default                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------ | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TZ`               | `Europe/Amsterdam`      | Timezone. Useful for accurate logs and scheduling. Example: `Europe/Moscow`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `HOST`         | Autodetect IP           | Domain or IPv4/IPv6 for WG clients. Example: `myhost.com`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `PORT`         | `10086`                 | WEB UI port. Example: `1125`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `ALLOW_FORWARD`    | -                       | By default, all interfaces and peers are isolated from each other. You can specify comma-separated interface (configuration) names to remove these restrictions. Example: `wg0,wg1`                                                                                                                                                                                                                                                                                                                                                                                                                                                             |


### _Environment variables of the `sb` service._

| Env                | Default                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------ | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TZ`               | `Europe/Amsterdam`      | Timezone. Useful for accurate logs and scheduling. Example: `Europe/Moscow`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `LOG_LEVEL`        | `fatal`                 | Log Level. One of: `trace` `debug` `info` `warn` `error` `fatal` `panic`. Example: `info`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `DNS_DIRECT`       | `https://dns.google`    | DNS for sing-box direct outbaund. Supported link types: `local` `tcp://` `udp://` `https://` `h3://` `tls://` `quic://`. Example: `udp://8.8.8.8`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `DNS_PROXY`        | `tls://one.one.one.one` | DNS for sing-box proxy outbaund. Supported link types are the same as `DNS_DIRECT`. Example: `quic://dns.adguard-dns.com`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `DNS_PROXY_TTL`    | `300`                   | Rewrite TTL in proxy DNS responses. Available numeric range (in seconds): from 0 to 600                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `ENABLE_ADGUARD`   | `false`                 | If set to `true`, includes a domain blocklist from [the repository](https://github.com/jinndi/adguard-filter-list-srs)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `BLOCK_GEOSITE`    | -                       | Geosite lists for blocking websites. You can specify one or more rules, separated by commas — combining direct links to `.srs` files (in the format `http://...` or `https://...`) or as file names from [the repository](https://github.com/SagerNet/sing-geosite/tree/rule-set) (without the `geosite-` prefix and **without the extension**) Example: if the repository contains a file named `geosite-google.srs`, specify `google` as the value. Note: the lists are updated automatically once per day. Another example: `category-ads-all,adblockplus,https://link.to/file.srs`                                                          |
| `BLOCK_GEOIP`      | -                       | Same as `BLOCK_GEOSITE`, but for IP-based routing. [Repository](https://github.com/SagerNet/sing-geoip/tree/rule-set). \*without the `geoip-` prefix and **without the extension**. Example: `ge,es,https://link.to/file.srs`                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `BLOCK_SITES`      | -                       | A comma-separated list of domain names or suffixes for blocking websites. Note: an entry can be a suffix (e.g., `example.org`), which will match subdomains (e.g., `sub.example.org`). A leading dot is not used for suffixes. Example: `ads.com,spam.com,fakenews.net`                                                                                                                                                                                                                                                                                                                                                                         |
| `PROXY_LINK`       | -                       | Proxy connection link. See: [Proxy links](https://github.com/jinndi/WGDashboard-sing-box/tree/dev#proxy-links)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `WARP_OVER_PROXY`  | `false`                 | If a link is specified in the `PROXY_LINK` setting, setting this parameter to `true` enables the route`WARP → PROXY → Internet`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `WARP_OVER_DIRECT` | `false`                 | If set to `true`, direct connections use the Cloudflare WARP proxy.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `ROUTE_CIDR`       | -                       | A comma-separated list of WireGuard interface IPv4 and IPv6 CIDR addresses to which the routing rules (all options below) will be applied. If no addresses are specified, the routing rules will apply to all interfaces. Example: `10.0.0.1/24,10.8.0.1/24,fd42:42:42::1/64`                                                                                                                                                                                                                                                                                                                                                                   |
| `ROUTE_FINAL`      | `direct`                | Default route. If none of the routing rules match, the default route will be applied — either `direct` (for direct internet access) or `proxy` (for access through a proxy server). Example: `proxy`                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `BYPASS_GEOSITE`   | -                       | A geosite used to bypass the `ROUTE_FINAL` rule, routing traffic in the opposite direction. You can specify one or more rules, separated by commas — combining direct links to `.srs` files (in the format `http://...` or `https://...`) and file names from the list (without the `geosite-` prefix and **without the extension**) available in [the repository](https://github.com/SagerNet/sing-geosite/tree/rule-set) Example: if the repository contains `geosite-google.srs`, specify `google` as the value. Note: the lists are updated automatically once per day. Example: `discord,https://link.to/file.srs,category-anticensorship` |
| `BYPASS_GEOIP`     | -                       | Same as `BYPASS_GEOSITE`, but for IP-based routing. [Repository](https://github.com/SagerNet/sing-geoip/tree/rule-set). \*without the `geoip-` prefix and **without the extension**. Example: `ru,be,https://link.to/file.srs`                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `PASS_SITES`       | -                       | A comma-separated list of domain names or suffixes. Traffic to domains matching these entries will be routed strictly following `ROUTE_FINAL`. Note: an entry can be a suffix (`example.org`), which allows matching subdomains (`sub.example.org`, etc.). A leading dot is not used for suffixes. Example: `vk.com,habr.com`                                                                                                                                                                                                                                                                                                                   |
| `BITTORRENT`       | `direct`                       | Route for BitTorrent traffic, one of: `direct`, `proxy`, or `block`.                                                                                                                                                                                                                                                                                                                  |
### Proxy links

> [!NOTE]
> To get the link, you can use the script from the [jinndi/sing-box-server](https://github.com/jinndi/sing-box-server) repository;
> it was largely created for this purpose and the links are fully compatible.

> [!WARNING]
> The values of URL parameters must be URL-encoded.
> Values written as `<>` should be replaced with actual data.
> Values enclosed in parentheses `()` are optional, but if you specify them, their values—if they are not enclosed in angle brackets `<>`— must be exactly as shown in the examples.
> The `sni` parameter for TLS security — if not specified, it will be set to the host address, provided that it is a domain name.

| Type                                                                                                                                                                                                                                                            | Format                                                                                                                                                                                                                    |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`WARP`](https://one.one.one.one/)<br />[`wireguard`](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)                                                                                                                                          | By default, if `PROXY_LINK` is not set                                                                                                                                                                                    |
| [`VLESS`](https://sing-box.sagernet.org/configuration/outbound/vless/) [`TCP-XTLS-Vision-REALITY`](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision-REALITY)                                                                               | `vless://<UUID>@<host>:<port>/?security=reality&pbk=<X25519-public-key>&sid=<shortID>&sni=<mask-domain>(&type=tcp&encryption=none&flow=xtls-rprx-vision&fp=<fingerprint>&alpn=<http/1.1,h2,h3>&packetEncoding=xudp#<any_name>)` |
| [`VLESS`](https://sing-box.sagernet.org/configuration/outbound/vless/) [`TCP-XTLS-Vision`](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-XTLS-Vision)                                                                                               | `vless://<UUID>@<host>:<port>/?security=tls(&type=tcp&encryption=none&flow=xtls-rprx-vision&sni=<cert-domain>&fp=<fingerprint>&alpn=<http/1.1,h2,h3>&packetEncoding=xudp#<any_name>)`                                           |
| [`VLESS`](https://sing-box.sagernet.org/configuration/outbound/vless/) [`TCP-TLS`](https://github.com/XTLS/Xray-examples/tree/main/VLESS-TCP-TLS)<br />[`multiplex (optional)`](https://sing-box.sagernet.org/configuration/shared/multiplex/)                  | `vless://<UUID>@<host>:<port>/?security=tls(&type=tcp&encryption=none&sni=<cert-domain>&fp=<fingerprint>&alpn=<http/1.1,h2,h3>&packetEncoding=xudp&multiplex=<protocol>#<any_name>)`                                            |
| [`TROJAN`](https://sing-box.sagernet.org/configuration/outbound/trojan/) [`TCP-TLS`](<https://github.com/XTLS/Xray-examples/tree/main/Trojan-TCP-TLS%20(minimal)>)<br />[`multiplex (optional)`](https://sing-box.sagernet.org/configuration/shared/multiplex/) | `trojan://<password>@<host>:<port>(/?type=tcp&security=tls&encryption=none&sni=<cert-domain>&fp=<fingerprint>&alpn=<http/1.1,h2,h3>&multiplex=<protocol>#<any_name>)`                                                           |
| [`Shadowsocks-2022`](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/)<br />[`multiplex (optional)`](https://sing-box.sagernet.org/configuration/shared/multiplex/)                                                                             | `ss://<Base64-encoded(<method>:<password>(:<user_password>)>@<host>:<port>(/?type=tcp&multiplex=<protocol>#<any_name>)`                                 |
| [`Socks5`](https://sing-box.sagernet.org/configuration/inbound/socks/)<br />[`UoT v2 (optional)`](https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/)                                                                                             | `socks5://(<user>:<password>@)<host>:<port>(/?uot=true)`                                                                                                                         |
| [`WireGuard`](https://sing-box.sagernet.org/configuration/endpoint/wireguard/)                                                                                                                                                                                  | `wg://<host>:<port>/?pk=<private-key>&local_address=<ipv4-cidr,ipv6-cidr>&peer_public_key=<peer-public-key>(&mtu=<MTU>#<any_name>)`                                                                                             |
| [`Hysteria2`](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)                                                                                                                                                                                  | `hysteria2://<password>@<host>:<port>(/?security=tls&sni=<cert-domain>alpn=h3insecure=0#<any_name>)`                                                                                                                                             |
| [`TUIC`](https://sing-box.sagernet.org/configuration/outbound/tuic/)                                                                                                                                                                                            | `tuic://<UUID>:<password>@<host>:<port>(/?security=tls&sni=<cert-domain>&alpn=h3&insecure=0&congestion_control=<type>&udp_relay_mode=<type>#<any_name>)`                                                                                                |

### _Environment variables of the `caddy` service._

> [!WARNING]
> After setting up the reverse proxy, edit your compose.yml file and remove the ports mapping from the corresponding service.

| Env                  | Default               | Description                                                                                                                                                                                                                                   |
| -------------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TZ`               | `Europe/Amsterdam`      | Timezone. Useful for accurate logs and scheduling. Example: `Europe/Moscow`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `DOMAIN`             | -                     | Required. Domain linked to your server's IP.                                                                                                                                                                                                  |
| `EMAIL`              | -                     | Required. Your email adress, used when creating an ACME account with your CA.                                                                                                                                                                 |
| `PROXY`              | -                     | Addresses for the reverse proxy. You can add multiple values separated by commas. Each value must follow the format `<domain_or_ip>:<port>/<prefix>` or `<domain_or_ip>/<prefix>`. The **prefix will be passed** to the proxy backend itself. |
| `PROXY_STRIP_PREFIX` | - | Same as `PROXY`, except the **prefix will not be passed** to the proxy backend.  Example: `sb:10086/dashboard`                                                                                                                                                             |
| `LOG_LEVEL`          | `info`                | Log Level. Possible values: `debug`, `info`, `warn`, `error`, and very rarely, `panic`, `fatal`                                                                                                                                               |
