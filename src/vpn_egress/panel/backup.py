"""Backup: the whole state.json in one file, optionally encrypted.

  {"format": "vpn-egress-backup", "version": 1, "created": "2026-11-26T10:00:00Z",
   "state": {...}}                                     # plain
   "encrypted": {"kdf": "scrypt", "n": 32768, "r": 8, "p": 1,
                 "salt": "<b64>", "nonce": "<b64>", "data": "<b64>"}}   # or this

Encrypted: AES-256-GCM, key from the passphrase with scrypt. The file holds
every secret the server has (exit and pipe private keys), so the panel
suggests a passphrase. Peers' private keys are never stored, so they aren't
in it either: devices keep working after a restore because the pipe's own
key comes back.

A restore replaces state.json as a whole, after a snapshot of the current
one (the last SNAPSHOTS are kept; "undo" puts the newest back).
"""

from __future__ import annotations

import base64
import datetime
import json
import os
import secrets
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..router import apply as router_apply
from ..router import blocklists as router_blocklists
from ..router import pipe as router_pipe
from ..router.config import Config, ConfigError
from .state import read_json

FORMAT = "vpn-egress-backup"
VERSION = 1
AAD = b"vpn-egress-backup v1"
SCRYPT = {"n": 2**15, "r": 8, "p": 1}
MAX_SIZE = 5 * 1024 * 1024
SNAPSHOTS = 5
PENDING_TTL = 900  # seconds an uploaded backup waits for "Restore"


class BackupError(ValueError):
    pass


def _key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode())


def export(state: dict, passphrase: str = "") -> bytes:
    doc = {
        "format": FORMAT,
        "version": VERSION,
        "created": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if passphrase:
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        data = AESGCM(_key(passphrase, salt, **SCRYPT)).encrypt(nonce, json.dumps(state).encode(), AAD)
        b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
        doc["encrypted"] = {"kdf": "scrypt", **SCRYPT, "salt": b64(salt), "nonce": b64(nonce), "data": b64(data)}
    else:
        doc["state"] = state
    return (json.dumps(doc, indent=2) + "\n").encode()


def is_encrypted(raw: bytes) -> bool:
    try:
        return "encrypted" in json.loads(raw)
    except (ValueError, TypeError):
        return False


def read(raw: bytes, passphrase: str = "") -> tuple[dict, str]:
    """(state, created) from a backup file."""
    if len(raw) > MAX_SIZE:
        raise BackupError("The file is too large to be a backup")
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise BackupError("Not a backup file (not JSON)") from exc
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise BackupError("Not a vpn-egress backup file")
    if doc.get("version") != VERSION:
        raise BackupError(f"Backup version {doc.get('version')} is not supported by this version")
    created = str(doc.get("created", ""))[:40]
    try:
        created = datetime.datetime.fromisoformat(created).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        pass
    enc = doc.get("encrypted")
    if enc is None:
        state = doc.get("state")
    else:
        if not passphrase:
            raise BackupError("This backup is encrypted: enter its passphrase")
        try:
            if enc.get("kdf") != "scrypt" or not all(isinstance(enc.get(k), int) for k in ("n", "r", "p")):
                raise BackupError("Unknown encryption parameters")
            if not (2**10 <= enc["n"] <= 2**20 and 1 <= enc["r"] <= 32 and 1 <= enc["p"] <= 16):
                raise BackupError("Encryption parameters out of range")
            salt, nonce, data = (base64.b64decode(enc[k], validate=True) for k in ("salt", "nonce", "data"))
            key = _key(passphrase, salt, enc["n"], enc["r"], enc["p"])
            state = json.loads(AESGCM(key).decrypt(nonce, data, AAD))
        except InvalidTag as exc:
            raise BackupError("Wrong passphrase (or the file was changed)") from exc
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise BackupError("The encrypted part of the backup is damaged") from exc
    if not isinstance(state, dict):
        raise BackupError("The backup has no state")
    return state, created


def check(state: dict, pipe_addresses: list[str] | None) -> list[str]:
    """Run the router's own checks, so a restore can't leave it with a state
    it refuses. pipe_addresses: the server's pipe subnets (None: unknown)."""
    errors = []
    try:
        router_apply.validate(state)
    except router_apply.StateError as exc:
        errors.append(f"Exits and routing: {exc}")
    if state.get("pipe") and pipe_addresses:
        try:
            cfg = Config.from_env({"EGRESS_PIPE_ADDRESSES": ",".join(pipe_addresses)})
            router_pipe.validate(state["pipe"], cfg)
        except router_pipe.PipeError as exc:
            errors.append(f"Pipe: {exc} (the backup's peers must fit this server's pipe subnets)")
        except ConfigError:
            pass
    if isinstance(state.get("dns"), dict):
        try:
            router_blocklists.validate(state["dns"])
        except ValueError as exc:
            errors.append(f"DNS: {exc}")
    traffic = state.get("traffic")
    if traffic is not None:
        a = traffic.get("allowance") if isinstance(traffic, dict) else "bad"
        if a is not None and (not isinstance(a, int) or isinstance(a, bool) or a <= 0):
            errors.append("Traffic: bad allowance")
    return errors


def summary(state: dict) -> dict:
    """What's in a state, for showing a backup next to the current one."""

    def names(items):
        return [i.get("name", "?") for i in items if isinstance(i, dict)] if isinstance(items, list) else []

    pipe = state.get("pipe") if isinstance(state.get("pipe"), dict) else {}
    dns = state.get("dns") if isinstance(state.get("dns"), dict) else None
    traffic = state.get("traffic") if isinstance(state.get("traffic"), dict) else None
    default = state.get("default") if isinstance(state.get("default"), dict) else {}
    exit_names = {"direct": "This server", "block": "Block"}
    exit_names.update({e.get("id"): e.get("name", "?") for e in state.get("exits", []) if isinstance(e, dict)})
    return {
        "exits": names(state.get("exits")),
        "lists": names(state.get("lists")),
        "default": exit_names.get(default.get("exit", "direct"), "?"),
        "pipe": bool(pipe.get("private_key")),
        "peers": names(pipe.get("peers")),
        "blocklists": len(dns.get("lists", [])) if dns else None,
        "dns_rules": len([x for x in dns.get("block", []) + dns.get("allow", []) if x.split("#")[0].strip()])
        if dns
        else None,
        "allowance": traffic.get("allowance") if traffic else "default",
    }


# --- pending uploads and snapshots (files in the state directory) ---------------------


def _write(path: Path, data: dict, mode: int = 0o600) -> None:
    """Atomically, and never readable by others (these hold private keys)."""
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.unlink(missing_ok=True)
    with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def save_pending(state_dir: Path, state: dict, created: str) -> str:
    token = secrets.token_urlsafe(16)
    _write(state_dir / ".pending-restore.json", {"token": token, "at": time.time(), "created": created, "state": state})
    return token


def take_pending(state_dir: Path, token: str) -> tuple[dict, str] | None:
    path = state_dir / ".pending-restore.json"
    pending = read_json(path)
    if pending is None:
        return None
    path.unlink(missing_ok=True)
    if not token or not secrets.compare_digest(str(pending.get("token", "")), token):
        return None
    if time.time() - float(pending.get("at", 0)) > PENDING_TTL or not isinstance(pending.get("state"), dict):
        return None
    return pending["state"], str(pending.get("created", ""))


def drop_pending(state_dir: Path) -> None:
    (state_dir / ".pending-restore.json").unlink(missing_ok=True)


def snapshots(state_dir: Path) -> list[Path]:
    d = state_dir / "snapshots"
    return sorted(d.glob("state-*.json")) if d.is_dir() else []


def restore(state_dir: Path, state: dict) -> None:
    """Snapshot the current state.json, then replace it."""
    current = state_dir / "state.json"
    if current.exists():
        d = state_dir / "snapshots"
        d.mkdir(mode=0o700, exist_ok=True)
        stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%S%fZ")
        _write(d / f"state-{stamp}.json", read_json(current) or {})
        for old in snapshots(state_dir)[:-SNAPSHOTS]:
            old.unlink(missing_ok=True)
    _replace_state(state_dir, state)


def undo(state_dir: Path) -> str | None:
    """Put the newest snapshot back; returns its time, or None if there is none."""
    snaps = snapshots(state_dir)
    if not snaps:
        return None
    state = read_json(snaps[-1])
    if state is None:
        snaps[-1].unlink(missing_ok=True)
        return None
    _replace_state(state_dir, state)
    snaps[-1].unlink(missing_ok=True)
    return snapshot_time(snaps[-1])


def snapshot_time(path: Path) -> str:
    s = path.stem.removeprefix("state-")
    return f"{s[0:4]}-{s[4:6]}-{s[6:8]} {s[9:11]}:{s[11:13]} UTC"


def _replace_state(state_dir: Path, state: dict) -> None:
    _write(state_dir / "state.json", state, 0o640)  # as save_section writes it
