"""Small helpers around ip, nft and friends. Nothing goes through a shell."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path


def run(*args: str, input: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input, text=True, capture_output=True, check=check)


def ip_json(*args: str) -> list[dict]:
    out = run("ip", "-j", *args).stdout.strip()
    data = json.loads(out) if out else []
    return [d for d in data if d]


def nft_apply(script: str) -> None:
    """Check, then load an nft script (one transaction)."""
    with tempfile.NamedTemporaryFile("w", prefix="vpn-egress-", suffix=".nft") as tmp:
        tmp.write(script)
        tmp.flush()
        run("nft", "-c", "-f", tmp.name)
        run("nft", "-f", tmp.name)


def write_if_changed(path: Path, text: str, mode: int = 0o644) -> bool:
    if path.exists() and path.read_text() == text:
        return False
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)
    return True


def write_json(path: Path, data: dict, uid: int) -> None:
    """Status files: readable by the panel (which runs as `uid`)."""
    tmp = path.with_name("." + path.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.chmod(tmp, 0o644)
    try:
        os.chown(tmp, uid, 0)
    except PermissionError:
        pass
    tmp.replace(path)
