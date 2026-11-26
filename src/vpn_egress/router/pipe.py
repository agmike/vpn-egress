"""The pipe: the AmneziaWG (or WireGuard) interface clients arrive on.

Managed here when EGRESS_PIPE_MANAGE is on and the state has a "pipe"
section (written by the panel):
  "pipe": {
    "private_key": "...",
    "obfuscation": {"Jc": 7, "Jmin": 52, ..., "H1": "100000-200000", "I1": "<b 0x...><r 8>"},
    "peers": [{"id": 1, "name": "Home router", "public_key": "...",
               "address": "10.66.0.2/32", "address6": "fd66::2/128",
               "routes": ["192.168.10.0/24", "0.0.0.0/0", "::/0"]}]   # networks behind it
  }
Port, addresses and MTU come from settings (the host firewall depends on
them). Without a pipe section the interface is left alone (e.g. managed by
awg-quick on the host), and only its status is reported.

A peer's networks are accepted as source addresses (its AllowedIPs) and, if
narrower than /0, routed to the pipe (proto 99 routes in the main table), so
other peers can reach them through this server. 0.0.0.0/0 and ::/0 only
mean "accept any source" (a router whose IPv6 prefix changes, say).
"""

from __future__ import annotations

import base64
import ipaddress
import re
import tempfile
import time
from pathlib import Path

from .config import Config
from .system import ip_json, run

OBFUSCATION_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5")
INT_KEYS = {"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4"}
RANGE_RE = re.compile(r"^[0-9]{1,10}(-[0-9]{1,10})?$")
SIGNATURE_RE = re.compile(r"^(<[a-z]{1,3}( [0-9a-fA-Fx]{1,4096})?>){1,64}$")
NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,40}$")
MAX_PEERS = 250
ROUTE_PROTO = "99"  # marks the routes we add for peers' networks


class PipeError(ValueError):
    pass


def _key(value, what):
    try:
        if isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32:
            return value
    except ValueError:
        pass
    raise PipeError(f"{what}: bad key")


def validate(pipe, cfg: Config) -> dict:
    if not isinstance(pipe, dict):
        raise PipeError("pipe must be an object")
    obf = pipe.get("obfuscation") or {}
    if not isinstance(obf, dict) or set(obf) - set(OBFUSCATION_KEYS):
        raise PipeError("pipe.obfuscation: unknown keys")
    clean_obf = {}
    for k in OBFUSCATION_KEYS:
        if k not in obf:
            continue
        v = obf[k]
        if k in INT_KEYS:
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 65535:
                raise PipeError(f"pipe.obfuscation.{k}: must be an integer")
        elif k.startswith("H"):
            if not isinstance(v, str | int) or not RANGE_RE.fullmatch(str(v)):
                raise PipeError(f"pipe.obfuscation.{k}: must be a number or a range")
        elif not isinstance(v, str) or not SIGNATURE_RE.fullmatch(v.replace("> <", "><")):
            raise PipeError(f"pipe.obfuscation.{k}: bad signature")
        clean_obf[k] = v
    nets4 = [i.network for i in cfg.pipe_addresses if i.version == 4]
    nets6 = [i.network for i in cfg.pipe_addresses if i.version == 6]
    peers, seen_ids, seen_keys = [], set(), set()
    raw_peers = pipe.get("peers", [])
    if not isinstance(raw_peers, list) or len(raw_peers) > MAX_PEERS:
        raise PipeError(f"pipe.peers: at most {MAX_PEERS}")
    for n, p in enumerate(raw_peers):
        what = f"pipe.peers[{n}]"
        if not isinstance(p, dict):
            raise PipeError(f"{what}: must be an object")
        pid = p.get("id")
        if not isinstance(pid, int) or isinstance(pid, bool) or not 1 <= pid <= 10000 or pid in seen_ids:
            raise PipeError(f"{what}: bad or duplicate id")
        seen_ids.add(pid)
        name = p.get("name")
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise PipeError(f"{what}: bad name")
        pub = _key(p.get("public_key"), what)
        if pub in seen_keys:
            raise PipeError(f"{what}: duplicate public key")
        seen_keys.add(pub)
        allowed = []
        for field, nets in (("address", nets4), ("address6", nets6)):
            value = p.get(field)
            if value in (None, ""):
                continue
            try:
                addr = ipaddress.ip_interface(value)
            except ValueError as exc:
                raise PipeError(f"{what}: bad {field}") from exc
            if addr.network.prefixlen != addr.max_prefixlen or not any(addr.ip in net for net in nets):
                raise PipeError(f"{what}: {field} must be a single address in the pipe subnet")
            allowed.append(str(addr.network))
        routes = p.get("routes", [])
        if not isinstance(routes, list) or len(routes) > 64:
            raise PipeError(f"{what}: bad routes")
        for r in routes:
            try:
                allowed.append(str(ipaddress.ip_network(r, strict=False)))
            except (ValueError, TypeError) as exc:
                raise PipeError(f"{what}: bad route {r!r}") from exc
        if not allowed:
            raise PipeError(f"{what}: needs an address or routes")
        nets = [str(n) for n in (ipaddress.ip_network(r, strict=False) for r in routes) if n.prefixlen > 0]
        peers.append({"id": pid, "name": name, "public_key": pub, "allowed": allowed, "networks": nets})
    return {"private_key": _key(pipe.get("private_key"), "pipe"), "obfuscation": clean_obf, "peers": peers}


def render(pipe: dict, cfg: Config) -> str:
    lines = ["[Interface]", f"PrivateKey = {pipe['private_key']}", f"ListenPort = {cfg.pipe_port}"]
    lines += [f"{k} = {v}" for k, v in pipe["obfuscation"].items()]
    for p in pipe["peers"]:
        lines += ["", "[Peer]", f"PublicKey = {p['public_key']}", f"AllowedIPs = {', '.join(p['allowed'])}"]
    return "\n".join(lines) + "\n"


def exists(cfg: Config) -> bool:
    return Path(f"/sys/class/net/{cfg.pipe_iface}").exists()


def apply(pipe: dict, cfg: Config, last: list[str]) -> None:
    """Create/converge the interface. `last` holds the last config applied."""
    iface = cfg.pipe_iface
    kind = "amneziawg" if cfg.pipe_tool == "awg" else "wireguard"
    created = False
    if not exists(cfg):
        run("ip", "link", "add", iface, "type", kind)
        created = True
    conf = render(pipe, cfg)
    if created or not last or last[0] != conf:
        with tempfile.NamedTemporaryFile("w", prefix="pipe-", delete=True) as tmp:
            tmp.write(conf)
            tmp.flush()
            # syncconf only applies differences: connected peers stay connected.
            run(cfg.pipe_tool, "syncconf", iface, tmp.name)
        last[:] = [conf]
    for family, fam in (("inet", "-4"), ("inet6", "-6")):
        want = sorted(str(a) for a in cfg.pipe_addresses if (a.version == 4) == (fam == "-4"))
        have = sorted(
            f"{a['local']}/{a['prefixlen']}"
            for link in ip_json("addr", "show", "dev", iface)
            for a in link.get("addr_info", [])
            if a.get("family") == family and a.get("scope") == "global"
        )
        if have != want:
            run("ip", fam, "addr", "flush", "dev", iface, "scope", "global")
            for a in want:
                run("ip", fam, "addr", "add", a, "dev", iface)
    run("ip", "link", "set", iface, "mtu", str(cfg.pipe_mtu), "up")
    sync_routes(pipe, iface)


def sync_routes(pipe: dict, iface: str) -> None:
    """Routes for the networks behind peers, so other peers reach them."""
    want = {n for p in pipe["peers"] for n in p.get("networks", [])}
    for fam in ("-4", "-6"):
        have = {r.get("dst") for r in ip_json(fam, "route", "show", "proto", ROUTE_PROTO)}
        for dst in have - want:
            run("ip", fam, "route", "del", dst, "proto", ROUTE_PROTO, check=False)
        for dst in sorted(want - have):
            if (":" in dst) == (fam == "-6"):
                run("ip", fam, "route", "replace", dst, "dev", iface, "proto", ROUTE_PROTO)


def status(cfg: Config, pipe: dict | None) -> dict:
    """What the panel shows (no secrets)."""
    peers = []
    out = run(cfg.pipe_tool, "show", cfg.pipe_iface, "dump", check=False).stdout.splitlines()
    server_pub = out[0].split("\t")[1] if out and len(out[0].split("\t")) > 1 else None
    for line in out[1:]:  # the first line is the interface itself
        f = line.split("\t")
        if len(f) < 8:
            continue
        hs = int(f[4])
        peers.append(
            {
                "public_key": f[0],
                "endpoint": None if f[2] == "(none)" else f[2],
                "allowed_ips": f[3],
                "handshake_age": int(time.time()) - hs if hs else None,
                "rx": int(f[5]),
                "tx": int(f[6]),
            }
        )
    return {
        "interface": cfg.pipe_iface,
        "managed": cfg.pipe_manage,
        "configured": pipe is not None,
        "public_key": server_pub,
        "port": cfg.pipe_port,
        "addresses": [str(a) for a in cfg.pipe_addresses],
        "endpoint": cfg.pipe_endpoint,
        "client_mtu": cfg.pipe_client_mtu,
        "peers": peers,
    }
