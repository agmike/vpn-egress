# vpn-egress

Self-hosted egress router: traffic arriving through a WireGuard (or AmneziaWG) tunnel
leaves from the server's own address, or through one of several VPN provider exits,
picked per domain or IP list in a small web panel.

> [!WARNING]
> **Early development — not ready for use.**
>
> - This is a personal project, built for my own homelab first. The code is **largely
>   written with an AI coding assistant (Claude)** and reviewed by me. Expect rough
>   edges, breaking changes and bugs — use at your own risk.
> - It is **not affiliated with any VPN provider**. You need your own provider accounts
>   and are responsible for following their terms and your local laws.
> - No warranty of any kind (see [LICENSE](LICENSE)). Issues and suggestions are welcome,
>   but support is best-effort.

## What it does

- **Exits:** paste a provider's WireGuard `.conf` (Proton, Nord, …); each becomes a
  kernel WireGuard tunnel, IPv4 and IPv6.
- **Routing:** ordered lists, each sent to an exit, **This server** or **Block**; first match
  wins (for domains too). Entries: domains with subdomains (`example.com`), whole TLDs (`jp`),
  GeoIP countries and services (`JP`, `NETFLIX`), ASNs (`AS2906`), addresses and ranges, and
  remote lists by URL (plain, hosts, dnsmasq, RPZ or JSON; refreshed daily). Per list: kill
  switch, lookups through the exit's own DNS. A catch-all (**Everything else**) picks where
  the rest goes; private and local destinations always stay local.
- **DNS:** dnsmasq on the tunnel with blocklists edited in the panel; plain DNS from the
  tunnel is redirected to it and DNS-over-TLS/QUIC is refused.
- **Pipe (optional):** the router can own the tunnel clients arrive on: server key and
  AmneziaWG obfuscation (**Recreate** makes new ones), devices with generated keys whose config
  is shown once as file, text and QR code, and sites (routers that keep their own key).
- **Panel:** OIDC sign-in only (any provider; access by group).

## How it runs

Two images, sharing one state directory:

| Image | Runs as | Does |
|---|---|---|
| `ghcr.io/agmike/vpn-egress-router` | root, host network, `NET_ADMIN` | applies the state: exit tunnels, nftables, ip rules, dnsmasq |
| `ghcr.io/agmike/vpn-egress-panel` | uid 10300, read-only, no capabilities | web UI on port 8080; writes the state file |

The panel never touches the host; the router re-validates everything it reads. Put the
panel behind a TLS reverse proxy.

The host provides the tunnel clients arrive on (e.g. `awg0`), IP forwarding for both
families, loose reverse-path filtering, and a firewall that forwards traffic from that
tunnel. The router answers traffic coming back by connection mark, so the networks
behind the tunnel need no routes on the server.

```yaml
services:
  router:
    image: ghcr.io/agmike/vpn-egress-router:0.1.0
    network_mode: host
    cap_add: [NET_ADMIN]
    environment:
      EGRESS_PIPE_IFACE: awg0
      EGRESS_DNS_UPSTREAMS: 9.9.9.9,149.112.112.112
    volumes: [./state:/state, ./data:/data]
    restart: unless-stopped
  panel:
    image: ghcr.io/agmike/vpn-egress-panel:0.1.0
    read_only: true
    cap_drop: [ALL]
    environment:
      PUBLIC_URL: https://egress.example.com
      OIDC_ISSUER: https://id.example.com
      OIDC_CLIENT_ID: vpn-egress
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      OIDC_ALLOWED_GROUPS: admins
      SESSION_SECRET: ${SESSION_SECRET}
    volumes: [./state:/state]
    restart: unless-stopped
```

The state directory must be writable by uid 10300.

## Settings

Router:

| Variable | Default | |
|---|---|---|
| `EGRESS_PIPE_IFACE` | `awg0` | tunnel the clients arrive on |
| `EGRESS_PIPE_TOOL` | `awg` | `awg` (AmneziaWG) or `wg`, for tunnel status |
| `EGRESS_DNS_UPSTREAMS` | `9.9.9.9,149.112.112.112` | resolvers dnsmasq asks |
| `EGRESS_DNS_CACHE_SIZE` | `10000` | |
| `EGRESS_DNS_REDIRECT` / `EGRESS_BLOCK_DOT` | `true` | force tunnel DNS to dnsmasq; refuse port 853 |
| `EGRESS_STATE_DIR` / `EGRESS_DATA_DIR` | `/state` / `/data` | |
| `EGRESS_STATE_UID` | `10300` | owner of status files (the panel's uid) |
| `EGRESS_APPLY_INTERVAL` / `EGRESS_BLOCKLIST_INTERVAL` / `EGRESS_SOURCE_INTERVAL` | `60` / `86400` / `86400` | seconds |
| `EGRESS_GEOIP_URL` / `EGRESS_ASN_URL` | MetaCubeX/meta-rules-dat | URL templates with `{name}` / `{asn}` |
| `EGRESS_PIPE_MANAGE` | `false` | create and configure the pipe interface from the panel's state |
| `EGRESS_PIPE_PORT` / `EGRESS_PIPE_MTU` | `51820` / `1380` | |
| `EGRESS_PIPE_ADDRESSES` | `10.66.0.1/24,fd66::1/64` | server addresses; peers get addresses from these subnets |
| `EGRESS_PIPE_ENDPOINT` / `EGRESS_PIPE_CLIENT_MTU` | — / `1280` | `host:port` and MTU written into client configs |

Panel: `PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_ALLOWED_GROUPS` (comma-separated; the provider must send a `groups` claim),
`SESSION_SECRET`, `STATE_DIR` (`/state`). The OIDC callback is `<PUBLIC_URL>/auth/callback`.

Blocklists start from `blocklist-defaults.json` in the state directory if present
(`{"lists": [{"name": "...", "url": "https://..."}], "block": [], "allow": []}`); after the
first save in the panel, the panel's copy is used.

## Development

```sh
uv sync --extra panel
uv run ruff check . && uv run pytest -q
```
