"""The panel's state file: read, validate, and save sections of it.

state.json is shared with the router, which reads "exits", "lists" and
"dns" and re-validates everything (this panel may be internet-facing); the
checks here only give friendly errors in the forms.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
LABEL_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,40}$")  # exit and list names (display only)
TLD_RE = re.compile(r"^[a-z][a-z0-9-]{1,62}$")  # a whole TLD, e.g. "jp"
URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[\x21-\x7e]*$")
MAX_LISTS = 30
MAX_DOMAINS = 10000


def read_json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def save_section(state_dir: Path, key: str, value) -> None:
    """Replace one top-level section of state.json, keeping the others."""
    path = state_dir / "state.json"
    state = read_json(path) or {}
    state[key] = value
    fd, tmp = tempfile.mkstemp(dir=state_dir, prefix=".state-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(state, fh, indent=2)
        fh.write("\n")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)


def dns_config(state_dir: Path) -> tuple[dict, str]:
    """The blocklist config in effect: the panel's, else the Ansible seed."""
    state = read_json(state_dir / "state.json") or {}
    if isinstance(state.get("dns"), dict):
        return state["dns"], "panel"
    seed = read_json(state_dir / "blocklist-defaults.json") or {}
    return seed, "defaults"


def parse_domains(text: str, what: str, errors: list[str]) -> list[str]:
    """Check each line; return the lines as typed (comments and single blank
    lines kept)."""
    lines: list[str] = []
    count = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        d = line.split("#", 1)[0].strip().lower().removeprefix("*.").rstrip(".")
        if d:
            count += 1
            if not DOMAIN_RE.match(d):
                errors.append(f"{what}: “{line.strip()}” is not a domain name")
        if line or (lines and lines[-1]):
            lines.append(line)
    while lines and not lines[-1]:
        lines.pop()
    if count > MAX_DOMAINS:
        errors.append(f"{what}: at most {MAX_DOMAINS} domains")
    return lines


def dns_from_form(form) -> tuple[dict, list[dict], list[str]]:
    """Build the dns section from the DNS page form.

    Returns (config, rows as entered, errors). Rows keep what was typed so the
    form can be shown again with the errors.
    """
    errors: list[str] = []
    rows: list[dict] = []
    try:
        count = min(int(form.get("list-count", "0")), MAX_LISTS + 1)
    except ValueError:
        count = 0
    lists, seen = [], set()
    for i in range(count):
        name = (form.get(f"list-{i}-name") or "").strip().lower()
        url = (form.get(f"list-{i}-url") or "").strip()
        enabled = form.get(f"list-{i}-enabled") == "on"
        remove = form.get(f"list-{i}-remove") == "on"
        if not name and not url:
            continue
        rows.append({"name": name, "url": url, "enabled": enabled})
        if remove:
            rows.pop()
            continue
        if not NAME_RE.match(name):
            errors.append(f"List “{name or '(no name)'}”: name must be lowercase letters, digits and dashes")
        elif name in seen:
            errors.append(f"List “{name}” appears twice")
        if not URL_RE.match(url):
            errors.append(f"List “{name or url}”: URL must start with https://")
        seen.add(name)
        lists.append({"name": name, "url": url, "enabled": enabled})
    if len(lists) > MAX_LISTS:
        errors.append(f"At most {MAX_LISTS} lists")
    block = parse_domains(form.get("block", ""), "Blocked domains", errors)
    allow = parse_domains(form.get("allow", ""), "Allowed domains", errors)
    return {"lists": lists, "block": block, "allow": allow}, rows, errors


# --- exits and lists ------------------------------------------------------------

MAX_ID = 200
MAX_ENTRIES = 5000


def _key_ok(value: str) -> bool:
    import base64

    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except ValueError:
        return False


def parse_wg_conf(text: str) -> tuple[dict | None, list[str]]:
    """A provider's WireGuard .conf → the exit's wireguard object."""
    import ipaddress

    errors: list[str] = []
    iface: dict[str, str] = {}
    peer: dict[str, str] = {}
    section = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" not in line or section not in ("interface", "peer"):
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        (iface if section == "interface" else peer).setdefault(k.lower(), v)
    priv, pub, endpoint = iface.get("privatekey", ""), peer.get("publickey", ""), peer.get("endpoint", "")
    if not _key_ok(priv):
        errors.append("The config has no valid PrivateKey")
    if not _key_ok(pub):
        errors.append("The config has no valid peer PublicKey")
    m = re.fullmatch(r"(?:\[([0-9a-fA-F:]+)\]|([0-9.]+)):([0-9]{1,5})", endpoint)
    if not m:
        errors.append("Endpoint must be an IPv4:port or [IPv6]:port (no host names)")
    v4 = v6 = None
    for a in (x.strip() for x in iface.get("address", "").split(",") if x.strip()):
        try:
            addr = ipaddress.ip_interface(a)
        except ValueError:
            errors.append(f"Bad Address {a}")
            continue
        if addr.version == 4 and v4 is None:
            v4 = str(addr)
        elif addr.version == 6 and v6 is None:
            v6 = str(addr)
    if v4 is None:
        errors.append("The config has no IPv4 Address")
    dns = []
    for d in (x.strip() for x in iface.get("dns", "").split(",") if x.strip()):
        try:
            dns.append(str(ipaddress.ip_address(d)))
        except ValueError:
            pass  # search domains and the like
    if errors:
        return None, errors
    return {"private_key": priv, "public_key": pub, "endpoint": endpoint, "address": v4, "address6": v6, "dns": dns}, []


def next_id(items: list[dict]) -> int | None:
    used = {i.get("id") for i in items}
    return next((n for n in range(1, MAX_ID + 1) if n not in used), None)


def parse_entries(text: str, errors: list[str]) -> list[str]:
    """Check each line; return the lines as typed (comments and single blank
    lines kept, so the list reads the same next time)."""
    import ipaddress

    lines: list[str] = []
    count = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        s = line.split("#", 1)[0].strip().lower()
        if s:
            count += 1
            try:
                ipaddress.ip_network(s, strict=False)
            except ValueError:
                d = s.removeprefix("*.").rstrip(".")
                if not (DOMAIN_RE.match(d) or TLD_RE.match(d)):
                    errors.append(f"“{line.strip()}” is not an address, range or domain")
        if line or (lines and lines[-1]):
            lines.append(line)
    while lines and not lines[-1]:
        lines.pop()
    if count > MAX_ENTRIES:
        errors.append(f"At most {MAX_ENTRIES} entries per list")
    if len(lines) > 2 * MAX_ENTRIES:
        errors.append(f"At most {2 * MAX_ENTRIES} lines per list")
    return lines


def list_from_form(form, exits: list[dict], errors: list[str]) -> dict:
    name = (form.get("name") or "").strip()
    if not LABEL_RE.match(name):
        errors.append("Name must be 1–40 characters")
    try:
        exit_id = int(form.get("exit", ""))
    except ValueError:
        exit_id = 0
    if exit_id not in {e.get("id") for e in exits}:
        errors.append("Pick an exit")
    return {
        "name": name,
        "exit": exit_id,
        # Kill switch on: block the list's traffic while its exit is down.
        "when_down": "block" if form.get("kill_switch") == "on" else "direct",
        "resolve_via_exit": form.get("resolve_via_exit") == "on",
        "entries": parse_entries(form.get("entries", ""), errors),
    }
