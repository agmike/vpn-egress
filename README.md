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
  kernel WireGuard tunnel, IPv4 and IPv6. Each has an optional "config expires" date (new ones
  default to a year ahead); the Status page warns 30 days before.
- **Routing:** ordered lists, each sent to an exit, **This server** or **Block**; first match
  wins (for domains too). Entries: domains with subdomains (`example.com`), whole TLDs (`jp`),
  GeoIP countries and services (`JP`, `NETFLIX`), ASNs (`AS2906`), addresses and ranges, and
  remote lists by URL (plain, hosts, dnsmasq, RPZ or JSON; refreshed daily). Per list: kill
  switch, lookups through the exit's own DNS. A catch-all (**Everything else**) picks where
  the rest goes; private and local destinations always stay local.
- **DNS:** dnsmasq on the tunnel with blocklists edited in the panel; plain DNS from the
  tunnel is redirected to it and DNS-over-TLS/QUIC is refused.
- **Pipe (optional):** the router can own the tunnel clients arrive on: server key and
  AmneziaWG obfuscation (**Recreate** makes new ones) and peers. A peer gets generated keys and a
  config shown once (file, text, QR code), or keeps its own key; optional networks behind it (a
  router's LANs) are accepted from it and routed to it, so other peers reach them. The host
  firewall must allow forwarding from the pipe to the pipe for that.
- **Transfer meter:** bytes sent and received on the uplink per calendar month (UTC), kept
  across restarts and reboots, with an optional allowance (OCI's free tier: 10 TB outbound),
  set or turned off on the Status page, a month-end projection and a warning at 80%.
- **Backup** (Maintenance page): one file with everything set in the panel (exits and keys, pipe key and peers,
  routing, DNS, allowance), encrypted with a passphrase (scrypt, AES-256-GCM) or plain. A
  restore shows what it would change, is checked with the router's own rules first, and can be
  undone (the last 5 states before a restore are kept in `snapshots/`).
- **Live log:** recent DNS queries and new connections from pipe clients, with the client (by
  peer name), the result (answered, cached, blocked), the list and exit that routed it; add a name
  or address to a list, block it or let a blocked one through, from the row. Kept in the router's
  memory only (the last 1000 of each) and handed to the panel only while the page is open.
- **Notifications:** through [Apprise](https://github.com/caronc/apprise) (Telegram, ntfy,
  email, Discord, … — any number of targets, shown masked): an exit down for two minutes, the
  router silent or failing, an exit config 30/7/1 days from expiring, traffic at 80%/100% of
  the allowance or on course to exceed it, and when each is resolved.
- **Maintenance page:** notifications, backup, API tokens, and the versions in use (vpn-egress,
  AmneziaWG tools and kernel module, WireGuard, dnsmasq, nftables, kernel).
- **API:** tokens made on the Maintenance page (shown once, stored hashed) for monitoring and
  scripted backups; see [API](#api).
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
| `EGRESS_LIVE_LOG` | `true` | dnsmasq query log and conntrack events for the Live page (memory only) |
| `EGRESS_TRAFFIC_IFACE` | default route's | interface the transfer meter counts |
| `EGRESS_TRAFFIC_ALLOWANCE` | — | monthly outbound allowance, e.g. `10TB` (decimal units), until one is set in the panel |

Panel: `PUBLIC_URL`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_ALLOWED_GROUPS` (comma-separated; the provider must send a `groups` claim),
`SESSION_SECRET`, `STATE_DIR` (`/state`). The OIDC callback is `<PUBLIC_URL>/auth/callback`.

Blocklists start from `blocklist-defaults.json` in the state directory if present
(`{"lists": [{"name": "...", "url": "https://..."}], "block": [], "allow": []}`); after the
first save in the panel, the panel's copy is used.

## API

Send `Authorization: Bearer <token>`; tokens are created on the Maintenance page with one of two
scopes, `status` or `backup` (which includes `status`).

- `GET /api/status` — for monitoring:
  ```json
  {"warnings": [{"kind": "exit_expiry", "level": "warn", "text": "Exit NL: config expires in 12 days (…)"}],
   "status_updated": 1764000000, "router_error": null,
   "exits": [{"name": "NL", "enabled": true, "up": true, "handshake_age": 40, "expires": "2027-11-24", "days_left": 363}],
   "traffic": {"month": "2026-11", "since": 1764000000, "tx": 812000000000, "rx": 95000000000,
               "allowance": 10000000000000, "projected_tx": 3100000000000},
   "pipe_peers": [{"handshake_age": 40, "rx": 306000000, "tx": 282000000}]}
  ```
  Warning kinds: `router` (no recent status, or an apply error), `exit_down`, `exit_expiry`,
  `traffic`; levels `warn` and `bad`.
- `POST /api/backup` (scope `backup`) — the backup file; with a body `{"passphrase": "..."}`
  it is encrypted, without one it holds the private keys in plain text.

```sh
curl -fsS -X POST -H "Authorization: Bearer $TOKEN" -d '{"passphrase": "…"}' \
  -o "egress-$(date +%F).json" https://egress.example.com/api/backup
```

## Development

```sh
uv sync --extra panel
uv run ruff check . && uv run pytest -q
```
