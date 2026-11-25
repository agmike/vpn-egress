"""Remote list sources: GeoIP countries and services, ASNs, and URL lists.

Each source is cached in the data directory and refreshed on a schedule; a
download that fails, comes back empty or shrinks by more than half keeps the
last good copy. GeoIP and ASN sources contribute IP ranges only; URL lists
may also contain domains.

Formats understood (one entry per line unless JSON): addresses and ranges,
domains (also "*.name", hosts files, dnsmasq "server=/name/"/"local=/name/",
RPZ "name CNAME ."), "# comments". JSON documents (such as published cloud IP
range files) contribute every string value that is an IP range.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
HOSTS_PREFIXES = ("0.0.0.0", "127.0.0.1", "::", "::1")
TIMEOUT = 60
MAX_DOWNLOAD = 64 * 1024 * 1024
MAX_ENTRIES = 500_000
SHRINK_LIMIT = 0.5
USER_AGENT = "vpn-egress"


@dataclass(frozen=True)
class Source:
    kind: str  # "geoip", "asn" or "url"
    name: str  # "JP", "NETFLIX", "AS2906", or the URL

    def url(self, geoip_url: str, asn_url: str) -> str:
        if self.kind == "geoip":
            return geoip_url.format(name=self.name.lower())
        if self.kind == "asn":
            return asn_url.format(asn=self.name.upper())
        return self.name

    @property
    def key(self) -> str:
        return hashlib.sha256(f"{self.kind}:{self.name}".encode()).hexdigest()[:24]


@dataclass
class Entries:
    v4: set
    v6: set
    domains: set

    def __len__(self) -> int:
        return len(self.v4) + len(self.v6) + len(self.domains)


def parse(text: str, allow_domains: bool) -> Entries:
    out = Entries(set(), set(), set())
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            _walk_json(json.loads(text), out)
            return out
        except ValueError:
            pass
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("!", ";")):
            continue
        m = re.fullmatch(r"(?:local|server|address)=/([^/]+)/.*", line)
        parts = line.split()
        if m:
            token = m.group(1)
        elif len(parts) >= 2 and parts[0] in HOSTS_PREFIXES:
            token = parts[1]
        elif len(parts) == 3 and [p.lower() for p in parts[1:]] == ["cname", "."]:
            token = parts[0]
        elif len(parts) == 1:
            token = parts[0]
        else:
            continue
        if _add_network(token, out):
            continue
        if allow_domains:
            d = token.lower().removeprefix("*.").rstrip(".")
            if DOMAIN_RE.match(d) and d not in ("localhost.localdomain",):
                out.domains.add(d)
    return out


def _add_network(token: str, out: Entries) -> bool:
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    (out.v4 if net.version == 4 else out.v6).add(str(net))
    return True


def _walk_json(node, out: Entries) -> None:
    if isinstance(node, dict):
        for v in node.values():
            _walk_json(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_json(v, out)
    elif isinstance(node, str) and ("/" in node or ":" in node or node.count(".") == 3):
        _add_network(node, out)


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("larger than 64 MiB")
    return data.decode("utf-8", errors="replace")


class SourceCache:
    def __init__(self, cache_dir: Path, geoip_url: str, asn_url: str):
        self.dir = cache_dir
        self.geoip_url = geoip_url
        self.asn_url = asn_url

    def _paths(self, src: Source) -> tuple[Path, Path]:
        return self.dir / f"{src.key}.txt", self.dir / f"{src.key}.json"

    def meta(self, src: Source) -> dict:
        _, meta = self._paths(src)
        try:
            return json.loads(meta.read_text())
        except (FileNotFoundError, ValueError):
            return {}

    def load(self, src: Source) -> Entries | None:
        data, _ = self._paths(src)
        if not data.exists():
            return None
        return parse(data.read_text(), allow_domains=src.kind == "url")

    def refresh(self, sources: set[Source], max_age: float) -> None:
        """Download sources with no copy or one older than max_age seconds."""
        self.dir.mkdir(parents=True, exist_ok=True)
        now = time.time()
        for src in sorted(sources, key=lambda s: (s.kind, s.name)):
            meta = self.meta(src)
            data, meta_path = self._paths(src)
            if data.exists() and now - meta.get("checked", 0) < max_age:
                continue
            old = self.load(src)
            meta.update(checked=int(now), error=None)
            try:
                text = fetch(src.url(self.geoip_url, self.asn_url))
                new = parse(text, allow_domains=src.kind == "url")
                if not len(new):
                    raise ValueError("no entries")
                if len(new) > MAX_ENTRIES:
                    raise ValueError(f"more than {MAX_ENTRIES} entries")
                if old is not None and len(new) < len(old) * SHRINK_LIMIT:
                    raise ValueError(f"{len(new)} entries vs {len(old)} before")
                data.write_text(text)
                meta.update(updated=int(now), entries=len(new))
            except Exception as exc:  # network, HTTP, size, parse
                meta["error"] = str(exc)[:200]
            meta_path.write_text(json.dumps(meta))
