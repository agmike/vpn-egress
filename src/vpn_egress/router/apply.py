"""Make the host's exit routing match the panel's state file.

The state file is written by the panel (an internet-facing container), so
everything in it is validated here before it touches the host: names,
numbers, keys, addresses. Nothing from it reaches a shell.

State (JSON; a missing file means nothing configured; other sections, such
as "dns", are ignored here):
  {
    "exits": [
      {"id": 1, "name": "Provider NL", "enabled": true,
       "wireguard": {"private_key": "...", "public_key": "...",
                     "endpoint": "198.51.100.5:51820" | "[2001:db8::5]:51820",
                     "address": "10.64.0.2/32", "address6": "fd00:64::2/128",
                     "dns": ["10.64.0.1"]}}
    ],
    "lists": [                      # priority order: the first match wins
      {"id": 1, "name": "Streaming", "exit": 1, "when_down": "block",
       "resolve_via_exit": true,
       "entries": ["198.51.100.0/24", "2001:db8::/32", "example.com", "jp",
                   "# comments and blank lines are ignored"]}
    ]
  }

What it manages (both IP families unless noted):
  - a kernel WireGuard interface per enabled exit, egx<id>, listen port
    51900 + id, with the exit's IPv4 and (optional) IPv6 address
  - a routing table per exit, 1000 + id: default via egx<id> while the exit
    had a handshake in the last 5 minutes (IPv6 only if the exit has it)
  - ip rules "oif egx<id> lookup 1000+id" (21000 + id), so sockets bound to
    an exit (dnsmasq resolving through it) are routed into it
  - the pipe-return rule (19000): packets marked 0x02000000 (see
    firewall.py) use table 999, default via the pipe
  - per list: fwmark 0x10000 + id and rules 20000 + 2*id (lookup the exit's
    table) and 20001 + 2*id (prohibit: when_down=block, the kill switch;
    when_down=direct falls through to the main table)
  - table inet vpn_egress_routes, updated in place (never recreated, so
    learned IPs survive): per list, sets l<id>_4/_6 (addresses and ranges)
    and d<id>_4/_6 (filled by dnsmasq from DNS answers, 2-day timeout)
  - dnsmasq's list config (nftset= lines) and servers-file (lists with
    resolve_via_exit ask the exit's DNS through the tunnel; while the exit is
    down, a list without kill switch uses the normal upstreams)
  - status.json in the state directory, for the panel (no secrets)
"""

from __future__ import annotations

import base64
import ipaddress
import json
import re
import tempfile
import time
from typing import Protocol

from .config import Config
from .firewall import RETURN_MARK
from .system import ip_json, nft_apply, run, write_if_changed, write_json

ROUTES_TABLE = "inet vpn_egress_routes"
EXIT_PREFIX = "egx"
EXIT_PORT_BASE = 51900
EXIT_MTU = 1420
TABLE_BASE = 1000
MARK_BASE = 0x10000
RULE_BASE = 20000
OIF_RULE_BASE = 21000
RULE_MAX = 21999
RETURN_TABLE = 999
RETURN_PRIO = 19000
MAX_ID = 200
MAX_ENTRIES = 5000
HANDSHAKE_FRESH = 300
LEARNED_TIMEOUT = "2d"

NAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,40}$")  # display only; everything is keyed by id
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
TLD_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")
FAMILIES = ("-4", "-6")


class StateError(ValueError):
    pass


class Dns(Protocol):
    def restart(self) -> None: ...
    def reload(self) -> None: ...
    def test(self) -> str | None: ...


# --- validation -----------------------------------------------------------------


def _id(value, what):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= MAX_ID:
        raise StateError(f"{what}: id must be an integer 1..{MAX_ID}")
    return value


def _name(value, what):
    if not isinstance(value, str) or not NAME_RE.match(value) or value != value.strip():
        raise StateError(f"{what}: name must be 1-40 printable characters")
    return value


def _key(value, what):
    if not isinstance(value, str):
        raise StateError(f"{what}: key must be a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise StateError(f"{what}: key is not base64") from exc
    if len(raw) != 32:
        raise StateError(f"{what}: key must be 32 bytes")
    return value


def _endpoint(value, what):
    m = re.fullmatch(r"(?:\[([0-9a-fA-F:]+)\]|([0-9.]+)):([0-9]{1,5})", value) if isinstance(value, str) else None
    if not m or not 1 <= int(m.group(3)) <= 65535:
        raise StateError(f"{what}: endpoint must be IPv4:port or [IPv6]:port")
    try:
        if m.group(1):
            ipaddress.IPv6Address(m.group(1))
        else:
            ipaddress.IPv4Address(m.group(2))
    except ValueError as exc:
        raise StateError(f"{what}: endpoint address is not valid") from exc
    return value


def _iface_addr(value, version, what, required):
    if value in (None, "") and not required:
        return None
    try:
        addr = ipaddress.ip_interface(value)
    except (ValueError, TypeError) as exc:
        raise StateError(f"{what}: bad IPv{version} address {value!r}") from exc
    if addr.version != version:
        raise StateError(f"{what}: expected an IPv{version} address, got {value!r}")
    return str(addr)


def classify(entries, what):
    """Split list lines into IPv4 networks, IPv6 networks and domains."""
    if not isinstance(entries, list) or len(entries) > 2 * MAX_ENTRIES:
        raise StateError(f"{what}: entries must be a list of at most {2 * MAX_ENTRIES} lines")
    v4, v6, domains = set(), set(), set()
    for e in entries:
        if not isinstance(e, str):
            raise StateError(f"{what}: entries must be strings")
        s = e.split("#", 1)[0].strip().lower()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError:
            d = s.removeprefix("*.").rstrip(".")
            if not (DOMAIN_RE.match(d) or TLD_RE.match(d)):
                raise StateError(f"{what}: {e!r} is not an address, range or domain") from None
            domains.add(d)
            continue
        (v4 if net.version == 4 else v6).add(str(net))
    if len(v4) + len(v6) + len(domains) > MAX_ENTRIES:
        raise StateError(f"{what}: at most {MAX_ENTRIES} entries")
    return sorted(v4), sorted(v6), sorted(domains)


def validate(state) -> dict:
    if not isinstance(state, dict):
        raise StateError("state must be an object")
    exits = {}
    for i, ex in enumerate(state.get("exits", [])):
        what = f"exits[{i}]"
        if not isinstance(ex, dict) or not isinstance(ex.get("wireguard"), dict):
            raise StateError(f"{what}: needs a wireguard object")
        eid = _id(ex.get("id"), what)
        if eid in exits:
            raise StateError(f"{what}: duplicate id {eid}")
        wg = ex["wireguard"]
        dns = wg.get("dns", [])
        if not isinstance(dns, list):
            raise StateError(f"{what}: dns must be a list")
        dns4 = []
        for d in dns:
            try:
                a = ipaddress.ip_address(d)
            except (ValueError, TypeError) as exc:
                raise StateError(f"{what}: bad DNS server {d!r}") from exc
            if a.version == 4:
                dns4.append(str(a))
        exits[eid] = {
            "id": eid,
            "name": _name(ex.get("name"), what),
            "enabled": bool(ex.get("enabled", True)),
            "private_key": _key(wg.get("private_key"), what),
            "public_key": _key(wg.get("public_key"), what),
            "endpoint": _endpoint(wg.get("endpoint"), what),
            "address": _iface_addr(wg.get("address"), 4, what, required=True),
            "address6": _iface_addr(wg.get("address6"), 6, what, required=False),
            "dns4": dns4[:1],
        }
    lists, seen = [], set()
    for i, lst in enumerate(state.get("lists", [])):
        what = f"lists[{i}]"
        if not isinstance(lst, dict):
            raise StateError(f"{what}: must be an object")
        lid = _id(lst.get("id"), what)
        if lid in seen:
            raise StateError(f"{what}: duplicate id {lid}")
        seen.add(lid)
        exit_id = _id(lst.get("exit"), what)
        if exit_id not in exits:
            raise StateError(f"{what}: exit {exit_id} does not exist")
        when_down = lst.get("when_down", "block")
        if when_down not in ("block", "direct"):
            raise StateError(f"{what}: when_down must be block or direct")
        v4, v6, domains = classify(lst.get("entries", lst.get("cidrs", [])), what)
        lists.append(
            {
                "id": lid,
                "name": _name(lst.get("name"), what),
                "exit": exit_id,
                "when_down": when_down,
                "resolve_via_exit": bool(lst.get("resolve_via_exit", False)),
                "v4": v4,
                "v6": v6,
                "domains": domains,
            }
        )
    return {"exits": exits, "lists": lists}


# --- exits --------------------------------------------------------------------------


def existing_exits() -> set[str]:
    names = (link.get("ifname", "") for link in ip_json("link", "show", "type", "wireguard"))
    return {n for n in names if re.fullmatch(rf"{EXIT_PREFIX}\d+", n)}


def configure_exit(ex: dict) -> None:
    iface = f"{EXIT_PREFIX}{ex['id']}"
    if iface not in existing_exits():
        run("ip", "link", "add", iface, "type", "wireguard")
    allowed = "0.0.0.0/0, ::/0" if ex["address6"] else "0.0.0.0/0"
    conf = (
        "[Interface]\n"
        f"PrivateKey = {ex['private_key']}\n"
        f"ListenPort = {EXIT_PORT_BASE + ex['id']}\n"
        "[Peer]\n"
        f"PublicKey = {ex['public_key']}\n"
        f"Endpoint = {ex['endpoint']}\n"
        f"AllowedIPs = {allowed}\n"
        "PersistentKeepalive = 25\n"
    )
    with tempfile.NamedTemporaryFile("w", prefix="egx-", delete=True) as tmp:
        tmp.write(conf)
        tmp.flush()
        # syncconf only applies differences: a working session is left alone.
        run("wg", "syncconf", iface, tmp.name)
    for family, fam, want in (("inet", "-4", ex["address"]), ("inet6", "-6", ex["address6"])):
        have = [
            f"{a['local']}/{a['prefixlen']}"
            for link in ip_json("addr", "show", "dev", iface)
            for a in link.get("addr_info", [])
            if a.get("family") == family and a.get("scope") == "global"
        ]
        if have != ([want] if want else []):
            run("ip", fam, "addr", "flush", "dev", iface, "scope", "global")
            if want:
                run("ip", fam, "addr", "add", want, "dev", iface)
    run("ip", "link", "set", iface, "mtu", str(EXIT_MTU), "up")


def handshake_age(tool: str, iface: str) -> int | None:
    out = run(tool, "show", iface, "latest-handshakes", check=False).stdout.split()
    if len(out) < 2 or out[1] == "0":
        return None
    return int(time.time()) - int(out[1])


def transfer(iface: str) -> tuple[int, int]:
    out = run("wg", "show", iface, "transfer", check=False).stdout.split()
    return (int(out[1]), int(out[2])) if len(out) >= 3 else (0, 0)


def set_exit_routes(ex: dict, up: bool) -> None:
    table, iface = str(TABLE_BASE + ex["id"]), f"{EXIT_PREFIX}{ex['id']}"
    for fam, has in (("-4", True), ("-6", bool(ex["address6"]))):
        if up and has:
            run("ip", fam, "route", "replace", "default", "dev", iface, "table", table)
        else:
            run("ip", fam, "route", "flush", "table", table, check=False)


# --- rules ------------------------------------------------------------------------------


def ensure_pipe_return(pipe: str) -> None:
    for fam in FAMILIES:
        run("ip", fam, "route", "replace", "default", "dev", pipe, "table", str(RETURN_TABLE))
        if not any(r.get("priority") == RETURN_PRIO for r in ip_json(fam, "rule", "show")):
            run(
                "ip",
                fam,
                "rule",
                "add",
                "priority",
                str(RETURN_PRIO),
                "fwmark",
                f"{RETURN_MARK:#x}/{RETURN_MARK:#x}",
                "lookup",
                str(RETURN_TABLE),
            )


def wanted_rules(exits: dict, lists: list) -> dict[int, tuple[str, str, str, str]]:
    want = {}
    for lst in lists:
        mark = hex(MARK_BASE + lst["id"])
        prio = RULE_BASE + 2 * lst["id"]
        want[prio] = ("fwmark", mark, "lookup", str(TABLE_BASE + lst["exit"]))
        if lst["when_down"] == "block":
            want[prio + 1] = ("fwmark", mark, "prohibit", "")
    for eid, ex in exits.items():
        if ex["enabled"]:
            want[OIF_RULE_BASE + eid] = ("oif", f"{EXIT_PREFIX}{eid}", "lookup", str(TABLE_BASE + eid))
    return want


def sync_rules(exits: dict, lists: list) -> None:
    want = wanted_rules(exits, lists)
    for fam in FAMILIES:
        have = {}
        for r in ip_json(fam, "rule", "show"):
            prio = r.get("priority", 0)
            if not RULE_BASE <= prio <= RULE_MAX:
                continue
            sel = ("fwmark", r.get("fwmark", "")) if "fwmark" in r else ("oif", r.get("oif", ""))
            act = ("prohibit", "") if r.get("action") == "prohibit" else ("lookup", str(r.get("table", "")))
            have[prio] = sel + act
        for prio, rule in have.items():
            if want.get(prio) != rule:
                run("ip", fam, "rule", "del", "priority", str(prio), check=False)
        for prio, rule in sorted(want.items()):
            if have.get(prio) == rule:
                continue
            sel, val, act, table = rule
            args = ["ip", fam, "rule", "add", "priority", str(prio), sel, val]
            args += ["lookup", table] if act == "lookup" else ["prohibit"]
            run(*args)


# --- nftables: table inet vpn_egress_routes, updated in place -------------------------


def render_routes(lists: list, pipe: str) -> str:
    """Idempotent: creates what's missing, refreshes the static sets and the
    chain, and leaves the learned d-sets' elements alone."""
    t = ROUTES_TABLE
    out = [f"add table {t}"]
    for lst in lists:
        i = lst["id"]
        for fam, addr_type in (("4", "ipv4_addr"), ("6", "ipv6_addr")):
            static = lst[f"v{fam}"]
            out.append(f"add set {t} l{i}_{fam} {{ type {addr_type}; flags interval; auto-merge; }}")
            out.append(f"flush set {t} l{i}_{fam}")
            if static:
                out.append(f"add element {t} l{i}_{fam} {{ {', '.join(static)} }}")
            out.append(f"add set {t} d{i}_{fam} {{ type {addr_type}; flags timeout; timeout {LEARNED_TIMEOUT}; }}")
    out += [
        f"add chain {t} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}",
        f"flush chain {t} prerouting",
        f'add rule {t} prerouting iifname != "{pipe}" return',
        f"add rule {t} prerouting ct direction reply return",
        # A flow already assigned to a list keeps that list's exit.
        f"add rule {t} prerouting ct mark & 0xffff != 0 meta mark set ct mark & 0xffff | {MARK_BASE:#x} return",
    ]
    for lst in lists:
        i, mark = lst["id"], hex(MARK_BASE + lst["id"])
        for fam, proto in (("4", "ip"), ("6", "ip6")):
            for kind in ("l", "d"):
                out.append(
                    f"add rule {t} prerouting {proto} daddr @{kind}{i}_{fam} "
                    f"ct mark set ct mark | {i} meta mark set {mark} return"
                )
    return "\n".join(out) + "\n"


def existing_sets() -> set[str]:
    res = run("nft", "-j", "list", "sets", "table", *ROUTES_TABLE.split(), check=False)
    if res.returncode != 0:
        return set()
    items = json.loads(res.stdout).get("nftables", [])
    return {it["set"]["name"] for it in items if "set" in it}


def sync_routes(lists: list, pipe: str, last: list[str]) -> None:
    """`last` holds the previously applied script (one element), to skip no-ops."""
    script = render_routes(lists, pipe)
    wanted = {f"{k}{lst['id']}_{f}" for lst in lists for k in ("l", "d") for f in ("4", "6")}
    stale = existing_sets() - wanted
    if last and last[0] == script and not stale:
        return
    # Sets of removed lists go after the chain flush that dropped their references.
    nft_apply(script + "".join(f"destroy set {ROUTES_TABLE} {n}\n" for n in sorted(stale)))
    last[:] = [script]


def learned_counts(list_id: int) -> dict[str, int]:
    counts = {}
    for fam in ("4", "6"):
        res = run("nft", "-j", "list", "set", *ROUTES_TABLE.split(), f"d{list_id}_{fam}", check=False)
        n = 0
        if res.returncode == 0:
            for it in json.loads(res.stdout).get("nftables", []):
                if "set" in it:
                    n = len(it["set"].get("elem", []))
        counts[fam] = n
    return counts


# --- dnsmasq ------------------------------------------------------------------------


def render_dnsmasq(state: dict, exit_up: dict[int, bool]) -> tuple[str, str]:
    table = ROUTES_TABLE.split()[1]
    lists_conf = ["# Written by vpn-egress: DNS answers for list domains fill the list's sets."]
    servers = ["# Written by vpn-egress: list domains resolved through their exit."]
    for lst in state["lists"]:
        if not lst["domains"]:
            continue
        i, doms = lst["id"], "/".join(lst["domains"])
        lists_conf.append(f"nftset=/{doms}/4#inet#{table}#d{i}_4,6#inet#{table}#d{i}_6")
        ex = state["exits"][lst["exit"]]
        if not (lst["resolve_via_exit"] and ex["enabled"] and ex["dns4"]):
            continue
        if exit_up.get(ex["id"]) or lst["when_down"] == "block":
            # Down with the kill switch on: still ask the exit, so lookups fail like the traffic.
            for d in lst["domains"]:
                servers.append(f"server=/{d}/{ex['dns4'][0]}@{EXIT_PREFIX}{ex['id']}")
    return "\n".join(lists_conf) + "\n", "\n".join(servers) + "\n"


def sync_dnsmasq(cfg: Config, state: dict, exit_up: dict[int, bool], dns: Dns) -> None:
    lists_conf, servers = render_dnsmasq(state, exit_up)
    lists_path = cfg.run_dir / "lists.conf"
    old_lists = lists_path.read_text() if lists_path.exists() else None
    if write_if_changed(lists_path, lists_conf):
        write_if_changed(cfg.run_dir / "servers.conf", servers)
        error = dns.test()
        if error:
            if old_lists is not None:
                lists_path.write_text(old_lists)
            raise StateError(f"dnsmasq rejected the list config: {error}")
        dns.restart()
    elif write_if_changed(cfg.run_dir / "servers.conf", servers):
        dns.reload()


# --- status / main -------------------------------------------------------------------


def pipe_status(cfg: Config) -> dict:
    peers = []
    out = run(cfg.pipe_tool, "show", cfg.pipe_iface, "dump", check=False).stdout.splitlines()
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
    return {"interface": cfg.pipe_iface, "peers": peers}


def apply(cfg: Config, dns: Dns, last_routes: list[str]) -> dict:
    status = {"updated": int(time.time()), "error": None, "exits": [], "lists": []}
    state_file = cfg.state_dir / "state.json"
    try:
        raw = json.loads(state_file.read_text()) if state_file.exists() else {}
        state = validate(raw)
    except (StateError, json.JSONDecodeError) as exc:
        # Keep the host as it is; tell the panel why nothing changed.
        status["error"] = f"state not applied: {exc}"
        status["pipe"] = pipe_status(cfg)
        write_json(cfg.state_dir / "status.json", status, cfg.state_uid)
        return status

    enabled = {eid for eid, ex in state["exits"].items() if ex["enabled"]}
    for iface in existing_exits() - {f"{EXIT_PREFIX}{eid}" for eid in enabled}:
        run("ip", "link", "del", iface, check=False)
        for fam in FAMILIES:
            run("ip", fam, "route", "flush", "table", str(TABLE_BASE + int(iface[len(EXIT_PREFIX) :])), check=False)

    exit_up = {}
    for eid, ex in sorted(state["exits"].items()):
        entry = {
            "id": eid,
            "name": ex["name"],
            "enabled": ex["enabled"],
            "up": False,
            "ipv6": bool(ex["address6"]),
            "endpoint": ex["endpoint"],
            "handshake_age": None,
            "rx": 0,
            "tx": 0,
        }
        if ex["enabled"]:
            configure_exit(ex)
            iface = f"{EXIT_PREFIX}{eid}"
            age = handshake_age("wg", iface)
            entry["up"] = age is not None and age < HANDSHAKE_FRESH
            entry["handshake_age"] = age
            entry["rx"], entry["tx"] = transfer(iface)
            set_exit_routes(ex, entry["up"])
        exit_up[eid] = entry["up"]
        status["exits"].append(entry)

    ensure_pipe_return(cfg.pipe_iface)
    # Lists whose exit is disabled keep their rules: with the kill switch they
    # stay blocked, without it they take the normal route.
    sync_routes(state["lists"], cfg.pipe_iface, last_routes)
    sync_rules(state["exits"], state["lists"])
    try:
        sync_dnsmasq(cfg, state, exit_up, dns)
    except StateError as exc:
        status["error"] = str(exc)
    for lst in state["lists"]:
        learned = learned_counts(lst["id"])
        status["lists"].append(
            {
                "id": lst["id"],
                "name": lst["name"],
                "exit": lst["exit"],
                "when_down": lst["when_down"],
                "resolve_via_exit": lst["resolve_via_exit"],
                "v4": len(lst["v4"]),
                "v6": len(lst["v6"]),
                "domains": len(lst["domains"]),
                "learned4": learned["4"],
                "learned6": learned["6"],
            }
        )
    status["pipe"] = pipe_status(cfg)
    write_json(cfg.state_dir / "status.json", status, cfg.state_uid)
    return status
