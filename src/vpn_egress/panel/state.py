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
GEO_RE = re.compile(r"^[A-Z][A-Z0-9-]{1,31}$")  # GeoIP country or service: "JP", "NETFLIX"
ASN_RE = re.compile(r"^[Aa][Ss][0-9]{1,10}$")  # "AS2906"
RESERVED_GEO = {"PRIVATE"}
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
            raw_entry = line.split("#", 1)[0].strip()
            if raw_entry in RESERVED_GEO:
                errors.append(f"“{raw_entry}” is reserved: private ranges always stay local")
            elif not (URL_RE.match(raw_entry) or ASN_RE.match(raw_entry) or GEO_RE.match(raw_entry)):
                try:
                    ipaddress.ip_network(s, strict=False)
                except ValueError:
                    d = s.removeprefix("*.").rstrip(".")
                    if not (DOMAIN_RE.match(d) or TLD_RE.match(d)):
                        errors.append(f"“{line.strip()}” is not an address, range, domain or source")
        if line or (lines and lines[-1]):
            lines.append(line)
    while lines and not lines[-1]:
        lines.pop()
    if count > MAX_ENTRIES:
        errors.append(f"At most {MAX_ENTRIES} entries per list")
    if len(lines) > 2 * MAX_ENTRIES:
        errors.append(f"At most {2 * MAX_ENTRIES} lines per list")
    return lines


SPECIAL_EXITS = {"direct": "This server", "block": "Block"}


def exit_from_form(value: str, exits: list[dict]) -> int | str | None:
    """A tunnel id, "direct" or "block"; None if it isn't one of those."""
    if value in SPECIAL_EXITS:
        return value
    try:
        exit_id = int(value)
    except ValueError:
        return None
    return exit_id if exit_id in {e.get("id") for e in exits if isinstance(e, dict)} else None


def list_from_form(form, exits: list[dict], errors: list[str]) -> dict:
    name = (form.get("name") or "").strip()
    if not LABEL_RE.match(name):
        errors.append("Name must be 1–40 characters")
    exit_id = exit_from_form(form.get("exit", ""), exits)
    if exit_id is None:
        errors.append("Pick an exit")
    return {
        "name": name,
        "exit": exit_id,
        # Kill switch on: block the list's traffic while its exit is down.
        "when_down": "block" if form.get("kill_switch") == "on" else "direct",
        "resolve_via_exit": form.get("resolve_via_exit") == "on",
        "entries": parse_entries(form.get("entries", ""), errors),
    }


# --- the pipe --------------------------------------------------------------------

# Looks like the start of a QUIC Initial packet (good on UDP 443).
DEFAULT_I1 = "<b 0xc300000001><b 0x08><r 8><b 0x0000><b 0x44d0><r 1200>"
OBFUSCATION_KEYS = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5")


def gen_keypair() -> tuple[str, str]:
    import base64

    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    key = X25519PrivateKey.generate()
    priv = key.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def public_key(private: str) -> str:
    import base64

    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    key = X25519PrivateKey.from_private_bytes(base64.b64decode(private))
    return base64.b64encode(key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()


def gen_obfuscation() -> dict:
    """Random AmneziaWG 2.0 parameters: junk packets, padding, header ranges."""
    import secrets

    r = secrets.SystemRandom()
    jmin = r.randint(40, 80)
    while True:
        s1, s2 = r.randint(20, 120), r.randint(20, 120)
        if s1 != s2 and s1 + 56 != s2:
            break
    starts = sorted(r.sample(range(16, 250), 4))
    heads = []
    for st in starts:
        a = st * (1 << 24) + r.randint(0, 1 << 20)
        heads.append(f"{a}-{a + r.randint(1 << 22, 1 << 23)}")
    return {
        "Jc": r.randint(4, 7),
        "Jmin": jmin,
        "Jmax": r.randint(jmin + 200, jmin + 600),
        "S1": s1,
        "S2": s2,
        "S3": r.randint(16, 48),
        "S4": r.randint(4, 16),
        "H1": heads[0],
        "H2": heads[1],
        "H3": heads[2],
        "H4": heads[3],
        "I1": DEFAULT_I1,
    }


def allocate_addresses(pipe: dict, server_addresses: list[str]) -> tuple[str | None, str | None]:
    """The lowest free host (from .2) in the pipe's IPv4 subnet, and the IPv6
    address with the same digits (10.66.0.11 → fd66::11)."""
    import ipaddress

    ifaces = [ipaddress.ip_interface(a) for a in server_addresses]
    used = {i.ip for i in ifaces}
    for p in pipe.get("peers", []):
        for field in ("address", "address6"):
            if p.get(field):
                used.add(ipaddress.ip_interface(p[field]).ip)
    v4 = next((i for i in ifaces if i.version == 4), None)
    v6 = next((i for i in ifaces if i.version == 6), None)
    if v4 is None:
        return None, None
    for n in range(2, v4.network.num_addresses - 1):
        a4 = v4.network.network_address + n
        a6 = v6.network.network_address + int(str(n), 16) if v6 else None
        if a4 not in used and (a6 is None or a6 not in used):
            return f"{a4}/32", (f"{a6}/128" if a6 else None)
    return None, None


def render_client_config(pipe: dict, peer: dict, pipe_status: dict, private_key: str | None) -> str:
    """A peer's config: complete with a generated private key, or a template
    for a peer that keeps its own key."""
    import ipaddress

    addrs = [a for a in (peer.get("address"), peer.get("address6")) if a]
    dns = [str(ipaddress.ip_interface(a).ip) for a in pipe_status.get("addresses", [])]
    nets = [n for n in peer.get("routes", []) if not n.endswith("/0")]
    lines = []
    if nets:
        lines.append(f"# Route {', '.join(nets)} into the tunnel without NAT; replies come back on their own.")
    lines += ["[Interface]", f"PrivateKey = {private_key or '<this peer’s own private key>'}"]
    if addrs:
        lines.append(f"Address = {', '.join(addrs)}")
    if dns:
        lines.append(f"DNS = {', '.join(dns)}")
    lines.append(f"MTU = {pipe_status.get('client_mtu', 1280)}")
    lines += [f"{k} = {v}" for k, v in pipe.get("obfuscation", {}).items()]
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {public_key(pipe['private_key'])}",
        f"Endpoint = {pipe_status.get('endpoint') or '<server:port>'}",
        "AllowedIPs = 0.0.0.0/0, ::/0",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"
