"""Merge DNS blocklists into a dnsmasq config file.

Configuration: the "dns" section of the panel's state.json when present,
otherwise the seed file blocklist-defaults.json in the state directory (if
any). Both look like
  {"lists": [{"name": "ads", "url": "https://...", "enabled": true}],
   "block": ["extra.example"], "allow": ["never-blocked.example"]}
The panel is internet-facing, so the config is validated here before use.

A list whose download fails or that shrinks by more than half keeps its last
cached copy. Quick mode only downloads lists without a cached copy or whose
URL changed. dnsmasq restarts only when the merged file changed. Status goes
to dns-status.json in the state directory.

Accepted line formats: bare domains, wildcard lists ("*.name"), hosts files
("0.0.0.0 name"), RPZ ("name CNAME ."), and dnsmasq "local=/name/" or
"server=/name/". Output: "local=/name/" (NXDOMAIN for the name and its
subdomains).
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

from .apply import Dns
from .config import Config
from .system import write_json

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")  # also a cache file name
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[\x21-\x7e]*$")
HOSTS_PREFIXES = ("0.0.0.0", "127.0.0.1", "::", "::1")
SHRINK_LIMIT = 0.5
TIMEOUT = 60
MAX_LISTS = 30
MAX_DOMAINS = 10000
MAX_DOWNLOAD = 64 * 1024 * 1024
USER_AGENT = "vpn-egress"


class ConfigError(ValueError):
    pass


def norm_domain(value) -> str | None:
    if not isinstance(value, str):
        return None
    d = value.strip().lower().rstrip(".")
    return d if DOMAIN_RE.match(d) else None


def validate(config) -> dict:
    if not isinstance(config, dict):
        raise ConfigError("dns config must be an object")
    lists = config.get("lists", [])
    if not isinstance(lists, list) or len(lists) > MAX_LISTS:
        raise ConfigError(f"lists must be a list of at most {MAX_LISTS}")
    out, seen = [], set()
    for i, entry in enumerate(lists):
        if not isinstance(entry, dict):
            raise ConfigError(f"lists[{i}] must be an object")
        name, url = entry.get("name"), entry.get("url")
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise ConfigError(f"lists[{i}]: bad name")
        if name in seen:
            raise ConfigError(f"lists[{i}]: duplicate name {name}")
        seen.add(name)
        if not isinstance(url, str) or not URL_RE.match(url):
            raise ConfigError(f"lists[{i}] ({name}): URL must be https://host/path")
        out.append({"name": name, "url": url, "enabled": bool(entry.get("enabled", True))})
    result = {"lists": out}
    for key in ("block", "allow"):
        values = config.get(key, [])
        if not isinstance(values, list) or len(values) > MAX_DOMAINS:
            raise ConfigError(f"{key} must be a list of at most {MAX_DOMAINS}")
        domains = []
        for v in values:
            d = norm_domain(v)
            if d is None:
                raise ConfigError(f"{key}: bad domain {v!r}")
            domains.append(d)
        result[key] = sorted(set(domains))
    return result


def parse(text: str) -> set[str]:
    out = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line or line.startswith(("!", ";")):
            continue
        m = re.fullmatch(r"(?:local|server|address)=/([^/]+)/.*", line)
        if m:
            name = m.group(1)
        else:
            parts = line.split()
            if len(parts) >= 2 and parts[0] in HOSTS_PREFIXES:
                name = parts[1]
            elif len(parts) == 3 and parts[1:] == ["cname", "."]:
                name = parts[0]  # RPZ: "name CNAME ." = NXDOMAIN
            elif len(parts) == 1:
                name = parts[0]
            else:
                continue
        name = name.removeprefix("*.").rstrip(".")
        if name in ("localhost", "localhost.localdomain", "local", "broadcasthost"):
            continue
        if DOMAIN_RE.match(name):
            out.add(name)
    return out


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("list larger than 64 MiB")
    return data.decode("utf-8", errors="replace")


def load_list(entry: dict, cache: Path, quick: bool) -> tuple[set[str], dict]:
    name, url = entry["name"], entry["url"]
    cached, cached_url = cache / f"{name}.txt", cache / f"{name}.url"
    old = set(cached.read_text().split()) if cached.exists() else set()
    same_url = cached_url.exists() and cached_url.read_text().strip() == url
    if quick and old and same_url:
        return old, {"name": name, "entries": len(old), "source": "cached"}
    if not same_url:
        old = set()  # a different URL: the old copy is no fallback for it
    try:
        new = parse(fetch(url))
    except Exception as exc:  # network, HTTP, decoding, size
        msg = f"download failed: {exc}"
        return old, {"name": name, "entries": len(old), "source": "cached" if old else "failed", "error": msg}
    if not new or (old and len(new) < len(old) * SHRINK_LIMIT):
        msg = f"got {len(new)} entries vs {len(old)} cached"
        return old, {"name": name, "entries": len(old), "source": "cached" if old else "failed", "error": msg}
    cached.write_text("\n".join(sorted(new)) + "\n")
    cached_url.write_text(url + "\n")
    return new, {"name": name, "entries": len(new), "source": "downloaded"}


def effective_config(state_dir: Path) -> tuple[dict, str]:
    state_file = state_dir / "state.json"
    if state_file.exists():
        state = json.loads(state_file.read_text())
        if isinstance(state, dict) and "dns" in state:
            return validate(state["dns"]), "panel"
    seed = state_dir / "blocklist-defaults.json"
    if seed.exists():
        return validate(json.loads(seed.read_text())), "defaults"
    return {"lists": [], "block": [], "allow": []}, "none"


def blocklist_path(cfg: Config) -> Path:
    return cfg.data_dir / "blocklist.conf"


def refresh(cfg: Config, dns: Dns, quick: bool) -> dict:
    cache = cfg.data_dir / "blocklists"
    cache.mkdir(parents=True, exist_ok=True)
    out = blocklist_path(cfg)
    status = {
        "updated": int(time.time()),
        "mode": "quick" if quick else "full",
        "config": None,
        "error": None,
        "lists": [],
        "blocked": None,
        "changed": False,
    }
    try:
        config, status["config"] = effective_config(cfg.state_dir)
    except (ConfigError, json.JSONDecodeError, OSError) as exc:
        status["error"] = f"config not applied: {exc}"
        write_json(cfg.state_dir / "dns-status.json", status, cfg.state_uid)
        return status

    names: set[str] = set()
    for entry in config["lists"]:
        if not entry["enabled"]:
            status["lists"].append({"name": entry["name"], "entries": 0, "source": "disabled"})
            continue
        got, info = load_list(entry, cache, quick)
        names |= got
        status["lists"].append(info)
    names |= set(config["block"])
    names -= set(config["allow"])
    status["blocked"] = len(names)

    text = "# Written by vpn-egress. Do not edit.\n" + "".join(f"local=/{n}/\n" for n in sorted(names))
    if not (out.exists() and out.read_text() == text):
        previous = out.read_text() if out.exists() else None
        out.write_text(text)
        error = dns.test()
        if error:
            if previous is not None:
                out.write_text(previous)
            status["error"] = f"dnsmasq rejected the merged list: {error}"
        else:
            dns.restart()
            status["changed"] = True
    write_json(cfg.state_dir / "dns-status.json", status, cfg.state_uid)
    return status
