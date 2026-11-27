"""Address lookups for the Live page: GeoIP, network (ASN) and your routing.

For an address, or each address a domain resolves to (asked of dnsmasq, so
the answer is the one pipe clients get):
  - GeoIP code from MetaCubeX's country.mmdb: a country ("JP"), or a service
    ("CLOUDFLARE", "GOOGLE") where the address belongs to one: the same codes
    list entries use
  - the network: ASN, organisation and announced prefix (GeoLite2-ASN.mmdb)
  - every routing list that matches it, and why (a range typed in the list,
    one of its sources, or learned from DNS answers), and the route a new
    connection takes: the first match, else the catch-all (or "local")

The databases are downloaded to the data directory and refreshed daily
(last good copy kept). The panel asks over a Unix socket in the state
directory (owned by the panel's uid): one JSON line in, one out.
"""

from __future__ import annotations

import ipaddress
import json
import os
import secrets
import socket
import socketserver
import struct
import threading
import time
import urllib.request
from pathlib import Path

import maxminddb

from . import apply as apply_mod
from .sources import USER_AGENT, SourceCache
from .system import run

MAX_DB = 128 * 1024 * 1024
LOCAL = [ipaddress.ip_network(n.strip()) for n in (apply_mod.LOCAL_V4 + "," + apply_mod.LOCAL_V6).split(",")]


class Databases:
    def __init__(self, directory: Path, urls: dict[str, str]):
        self.dir, self.urls = directory, {k: v for k, v in urls.items() if v}
        self.readers: dict[str, maxminddb.Reader] = {}
        self.lock = threading.Lock()
        for name in self.urls:
            self._open(name)

    def _path(self, name: str) -> Path:
        return self.dir / f"{name}.mmdb"

    def _open(self, name: str) -> None:
        path = self._path(name)
        if not path.exists():
            return
        try:
            reader = maxminddb.open_database(str(path))
        except (OSError, ValueError, maxminddb.InvalidDatabaseError):
            return
        with self.lock:
            old = self.readers.get(name)
            self.readers[name] = reader
        if old:
            old.close()

    def refresh(self, max_age: float) -> list[str]:
        """Download missing or old databases; returns errors."""
        self.dir.mkdir(parents=True, exist_ok=True)
        errors = []
        for name, url in self.urls.items():
            path = self._path(name)
            if path.exists() and time.time() - path.stat().st_mtime < max_age:
                continue
            tmp = path.with_name(f".{name}.download")
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=120) as resp, tmp.open("wb") as out:
                    total = 0
                    while chunk := resp.read(1 << 20):
                        total += len(chunk)
                        if total > MAX_DB:
                            raise ValueError("larger than 128 MiB")
                        out.write(chunk)
                maxminddb.open_database(str(tmp)).close()  # a damaged download never replaces a good copy
                tmp.replace(path)
                self._open(name)
            except Exception as exc:  # network, HTTP, size, format
                errors.append(f"{name} database: {str(exc)[:200]}")
                tmp.unlink(missing_ok=True)
                if path.exists():
                    os.utime(path)  # retry with the next refresh, not every minute
        return errors

    def get(self, name: str, ip: str) -> tuple[dict | None, int | None]:
        with self.lock:
            reader = self.readers.get(name)
        if reader is None:
            return None, None
        try:
            return reader.get_with_prefix_len(ip)
        except ValueError:
            return None, None

    def info(self) -> dict:
        out = {}
        for name in self.urls:
            path = self._path(name)
            out[name] = int(path.stat().st_mtime) if path.exists() else None
        return out


# --- DNS through dnsmasq ---------------------------------------------------------------


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode("idna") for p in name.rstrip(".").split(".")) + b"\0"


def _skip_name(msg: bytes, pos: int) -> int:
    while True:
        n = msg[pos]
        if n & 0xC0 == 0xC0:
            return pos + 2
        if n == 0:
            return pos + 1
        pos += n + 1


def parse_answers(msg: bytes, qid: int) -> list[str]:
    """A and AAAA records from a DNS response (CNAMEs are followed by dnsmasq)."""
    if len(msg) < 12:
        return []
    rid, _flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    if rid != qid:
        return []
    pos = 12
    for _ in range(qd):
        pos = _skip_name(msg, pos) + 4
    out = []
    for _ in range(an):
        pos = _skip_name(msg, pos)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[pos : pos + 10])
        pos += 10
        rdata = msg[pos : pos + rdlen]
        pos += rdlen
        if rtype == 1 and rdlen == 4:
            out.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == 28 and rdlen == 16:
            out.append(str(ipaddress.IPv6Address(rdata)))
    return out


def resolve(name: str, server: str, timeout: float = 4.0, port: int = 53) -> list[str]:
    found: list[str] = []
    for qtype in (1, 28):
        qid = secrets.randbelow(65536)
        query = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _qname(name) + struct.pack("!HH", qtype, 1)
        fam = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(query, (server, port))
                found += parse_answers(s.recv(4096), qid)
            except OSError:
                continue
    return list(dict.fromkeys(found))


# --- the lookup ----------------------------------------------------------------------


def learned(list_id: int, ip) -> bool:
    fam = "4" if ip.version == 4 else "6"
    res = run("nft", "get", "element", "inet", "vpn_egress_routes", f"d{list_id}_{fam}", f"{{ {ip} }}", check=False)
    return res.returncode == 0


def routing(ip, state: dict, cache: SourceCache | None, is_learned=learned) -> dict:
    """Which lists match the address, and why; and the route a new connection takes."""
    matches = []
    for lst in state["lists"]:
        reasons = []
        typed = lst["v4"] if ip.version == 4 else lst["v6"]
        if any(ip in ipaddress.ip_network(n) for n in typed):
            reasons.append({"kind": "range"})
        for src in sorted(lst["sources"], key=lambda s: (s.kind, s.name)):
            got = cache.load(src) if cache else None
            nets = (got.v4 if ip.version == 4 else got.v6) if got else ()
            if any(ip in ipaddress.ip_network(n) for n in nets):
                reasons.append({"kind": src.kind, "name": src.name})
        if is_learned(lst["id"], ip):
            reasons.append({"kind": "learned"})
        if reasons:
            matches.append({"list": lst["id"], "reasons": reasons})
    if matches:
        route = matches[0]["list"]
    elif any(ip in n for n in LOCAL if n.version == ip.version):
        route = "local"
    else:
        route = "default"
    return {"matches": matches, "route": route}


class Lookup:
    def __init__(self, cfg, cache: SourceCache, dbs: Databases, live=None):
        self.cfg, self.cache, self.dbs, self.live = cfg, cache, dbs, live
        self.dns_server = next((str(a.ip) for a in cfg.pipe_addresses if a.version == 4), None)

    def answer(self, query: str) -> dict:
        query = query.strip().lower().rstrip(".")
        try:
            raw = json.loads((self.cfg.state_dir / "state.json").read_text())
            state = apply_mod.validate(raw)
        except (OSError, ValueError, apply_mod.StateError):
            state = {"lists": []}
        out = {
            "query": query,
            "kind": "ip",
            "claim": None,
            "addresses": [],
            "databases": self.dbs.info(),
            "error": None,
        }
        try:
            ips = [ipaddress.ip_address(query)]
        except ValueError:
            if not apply_mod.DOMAIN_RE.match(query):
                out["error"] = "not an address or a domain name"
                return out
            out["kind"] = "domain"
            out["claim"] = self.live.list_for(query) if self.live else None
            if not self.dns_server:
                out["error"] = "no IPv4 pipe address to ask dnsmasq on"
                return out
            ips = [ipaddress.ip_address(a) for a in resolve(query, self.dns_server)]
            if not ips:
                out["error"] = "no addresses (blocked, or the name doesn't exist)"
        for ip in ips[:16]:
            geo, geo_prefix = self.dbs.get("country", str(ip))
            asn, asn_prefix = self.dbs.get("asn", str(ip))
            code = ((geo or {}).get("country") or {}).get("iso_code")
            out["addresses"].append(
                {
                    "ip": str(ip),
                    "geoip": {"code": code, "prefix": _net(ip, geo_prefix) if code else None},
                    "asn": {
                        "number": (asn or {}).get("autonomous_system_number"),
                        "org": (asn or {}).get("autonomous_system_organization"),
                        "prefix": _net(ip, asn_prefix) if asn else None,
                    },
                    **routing(ip, state, self.cache),
                }
            )
        return out


def _net(ip, prefix_len) -> str:
    return str(ipaddress.ip_network(f"{ip}/{prefix_len}", strict=False))


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(30)
        try:
            line = self.rfile.readline(4096)
            request = json.loads(line or b"{}")
            commands = getattr(self.server, "commands", None)
            if "cmd" in request and commands is not None:
                reply = commands(request)
            else:
                reply = self.server.lookup.answer(str(request.get("q", ""))[:253])
        except Exception as exc:  # a bad request or a bug: answer, don't die
            reply = {"error": f"lookup failed: {type(exc).__name__}"}
        self.wfile.write((json.dumps(reply) + "\n").encode())


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def serve(lookup: Lookup, path: Path, uid: int, commands=None) -> _Server:
    """commands: answers requests with a "cmd" (exit switches and the like)."""
    path.unlink(missing_ok=True)
    server = _Server(str(path), _Handler)
    server.lookup = lookup
    server.commands = commands
    os.chmod(path, 0o600)
    try:
        os.chown(path, uid, 0)  # the panel's uid; nobody else
    except PermissionError:
        pass
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
