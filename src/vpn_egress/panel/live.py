"""The Live page's data: the router's live.json, labelled for people.

The router only writes live.json while live-watch is fresh, so reading the
data also touches it. Clients are named after pipe peers (their address, or
a network behind them), routes after lists and exits.
"""

from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path

from .state import read_json

SPECIAL = {"direct": "This server", "block": "Block"}


def touch_watch(state_dir: Path) -> None:
    path = state_dir / "live-watch"
    try:
        os.utime(path)
    except FileNotFoundError:
        path.write_text("")


def _peers(state: dict) -> list[tuple[str, list]]:
    pipe = state.get("pipe") if isinstance(state.get("pipe"), dict) else {}
    out = []
    for p in pipe.get("peers", []) or []:
        if not isinstance(p, dict):
            continue
        nets = []
        for value in [p.get("address"), p.get("address6"), *(p.get("routes") or [])]:
            try:
                net = ipaddress.ip_network(value, strict=False) if value else None
            except ValueError:
                net = None
            if net is not None and net.prefixlen > 0:
                nets.append(net)
        out.append((str(p.get("name", "?")), nets))
    return out


def _client_name(addr: str, peers: list) -> str | None:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    best = None
    for name, nets in peers:
        for net in nets:
            if net.version == ip.version and ip in net and (best is None or net.prefixlen > best[1]):
                best = (name, net.prefixlen)
    return best[0] if best else None


def labelled(state_dir: Path, state: dict) -> dict:
    data = read_json(state_dir / "live.json")
    exits = {e.get("id"): str(e.get("name")) for e in state.get("exits", []) if isinstance(e, dict)}
    lists = {l.get("id"): l for l in state.get("lists", []) if isinstance(l, dict)}
    default = (state.get("default") or {}).get("exit", "direct") if isinstance(state.get("default"), dict) else "direct"
    peers = _peers(state)

    def exit_name(ref) -> str:
        return SPECIAL.get(ref) or exits.get(ref) or "?"

    def route(list_id) -> str:
        if list_id == 255:
            return f"Everything else → {exit_name(default)}"
        lst = lists.get(list_id)
        if lst is None:
            return f"Everything else → {exit_name(default)}" if list_id is None else f"list {list_id}"
        return f"{lst.get('name')} → {exit_name(lst.get('exit'))}"

    dns, conns = [], []
    for r in (data or {}).get("dns", []):
        dns.append({**r, "client_name": _client_name(r.get("client", ""), peers), "route": route(r.get("list"))})
    for r in (data or {}).get("conns", []):
        via = r.get("via")
        via_label = "Pipe" if via == "pipe" else exit_name(via)
        conns.append(
            {
                **r,
                "client_name": _client_name(r.get("client", ""), peers),
                "route": "Pipe peer" if via == "pipe" else route(r.get("list")),
                "via_label": via_label,
            }
        )
    return {
        "available": data is not None,
        "updated": (data or {}).get("updated"),
        "now": int(time.time()),
        "dns": dns,
        "conns": conns,
        "lists": [{"id": l.get("id"), "name": l.get("name")} for l in lists.values()],
    }
