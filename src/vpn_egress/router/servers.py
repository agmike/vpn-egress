"""Provider server lists, for an exit's fallback servers.

From qdm12/gluetun-servers (MIT, the data gluetun ships): one JSON file per
provider with each server's name, country, city, addresses, WireGuard public
key and features. Downloaded weekly to the data directory (last good copy
kept). Proton WireGuard keys work on every Proton server, so an exit can
move to another server with its own key; only the endpoint and the server's
public key change.

The data is a sample of the provider's network (a few servers per country),
refreshed by gluetun's maintainers every few weeks.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import time
import urllib.request
from pathlib import Path

from .sources import USER_AGENT

PROVIDERS = {"protonvpn": "Proton VPN"}
MAX_SIZE = 32 * 1024 * 1024
WG_PORT = 51820


def _valid_key(value) -> bool:
    import base64

    try:
        return isinstance(value, str) and len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


class ServerList:
    def __init__(self, directory: Path, url_template: str):
        self.dir, self.url_template = directory, url_template
        self._cache: dict[str, tuple[float, list[dict]]] = {}

    def path(self, provider: str) -> Path:
        return self.dir / f"{provider}.json"

    def refresh(self, max_age: float) -> list[str]:
        if not self.url_template:
            return []
        self.dir.mkdir(parents=True, exist_ok=True)
        errors = []
        for provider in PROVIDERS:
            path = self.path(provider)
            if path.exists() and time.time() - path.stat().st_mtime < max_age:
                continue
            try:
                url = self.url_template.format(provider=provider)
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    data = resp.read(MAX_SIZE + 1)
                if len(data) > MAX_SIZE:
                    raise ValueError("too large")
                if not self._parse(json.loads(data)):
                    raise ValueError("no WireGuard servers in it")
                tmp = path.with_name(f".{provider}.download")
                tmp.write_bytes(data)
                tmp.replace(path)
            except Exception as exc:  # network, HTTP, JSON
                errors.append(f"{provider} servers: {str(exc)[:200]}")
                if path.exists():
                    os.utime(path)  # retry with the next refresh
        return errors

    @staticmethod
    def _parse(doc) -> list[dict]:
        out = []
        for s in (doc or {}).get("servers", []) if isinstance(doc, dict) else []:
            if not isinstance(s, dict) or s.get("vpn") != "wireguard" or not _valid_key(s.get("wgpubkey")):
                continue
            ips = []
            for ip in s.get("ips") or []:
                try:
                    ips.append(ipaddress.ip_address(ip))
                except ValueError:
                    continue
            v4 = [str(i) for i in ips if i.version == 4]
            if not v4:
                continue
            out.append(
                {
                    "name": str(s.get("server_name") or s.get("hostname") or v4[0])[:40],
                    "country": str(s.get("country") or "")[:60],
                    "city": str(s.get("city") or "")[:60],
                    "endpoint": f"{v4[0]}:{WG_PORT}",
                    "public_key": s["wgpubkey"],
                    "ipv6": any(i.version == 6 for i in ips),
                    "special": bool(s.get("secure_core") or s.get("free") or s.get("tor")),
                }
            )
        return out

    def servers(self, provider: str) -> list[dict]:
        path = self.path(provider)
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            return []
        cached = self._cache.get(provider)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            parsed = self._parse(json.loads(path.read_text()))
        except (OSError, ValueError):
            parsed = []
        self._cache[provider] = (mtime, parsed)
        return parsed

    def countries(self, provider: str) -> list[dict]:
        counts: dict[str, list[int]] = {}
        for s in self.servers(provider):
            if s["special"]:
                continue
            c = counts.setdefault(s["country"], [0, 0])
            c[0] += 1
            c[1] += s["ipv6"]
        return [{"country": k, "servers": v[0], "ipv6": v[1]} for k, v in sorted(counts.items())]

    def candidates(self, provider: str, country: str, ipv6: bool, exclude: set[str]) -> list[dict]:
        """Regular servers in the country (IPv6-listed ones if asked), in random order."""
        found = [
            s
            for s in self.servers(provider)
            if s["country"] == country
            and not s["special"]
            and (s["ipv6"] or not ipv6)
            and s["name"] not in exclude
            and s["endpoint"] not in exclude
        ]
        random.shuffle(found)
        return found
