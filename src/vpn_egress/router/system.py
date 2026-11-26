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


def _first_line(*args: str) -> str | None:
    try:
        out = run(*args, check=False)
    except OSError:
        return None
    line = (out.stdout or out.stderr).strip().splitlines()
    return line[0] if line else None


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text().strip() or None
    except OSError:
        return None


def _tool_versions(pipe_tool: str) -> dict:
    import re

    def ver(line: str | None) -> str | None:
        m = re.search(r"v?([0-9]+(?:\.[0-9]+)+[0-9A-Za-z.+-]*)", line or "")
        return m.group(1) if m else None

    tools = {
        "wireguard_tools": ver(_first_line("wg", "--version")),
        "dnsmasq": ver(_first_line("dnsmasq", "--version")),
        "nftables": ver(_first_line("nft", "--version")),
    }
    if pipe_tool == "awg":
        tools["amneziawg_tools"] = ver(_first_line("awg", "--version"))
    return tools


_TOOLS: dict = {}


def versions(pipe_tool: str) -> dict:
    """Software versions for the panel: tools in this image (once), kernel
    and modules on the host (each time: a module can be reloaded)."""
    if not _TOOLS:
        _TOOLS.update(_tool_versions(pipe_tool))
    out = {"vpn_egress": os.environ.get("VPN_EGRESS_VERSION", "dev"), **_TOOLS, "kernel": os.uname().release}
    out["wireguard_module"] = _read("/sys/module/wireguard/version")
    if pipe_tool == "awg":
        out["amneziawg_module"] = _read("/sys/module/amneziawg/version")
    return out
