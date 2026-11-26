"""API tokens: for scripts and monitoring, next to the OIDC-protected panel.

state.json "api": {"tokens": [{"id": 1, "name": "health bot", "scope": "status",
                               "hash": "<sha256 hex>", "created": 1764000000}]}

A token is shown once when created; only its SHA-256 is stored (tokens are
random 256-bit values, so a plain hash is enough). Scopes:
  status  GET /api/status
  backup  that, and POST /api/backup (the file holds every private key)
When a token was last used goes to api-usage.json, not state.json: an API
call must not make the router re-apply the state.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

from .state import LABEL_RE, read_json

PREFIX = "vpe_"
SCOPES = {"status": ("status",), "backup": ("status", "backup")}
MAX_TOKENS = 20


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def tokens(state: dict) -> list[dict]:
    api = state.get("api")
    items = api.get("tokens") if isinstance(api, dict) else None
    return [t for t in items if isinstance(t, dict)] if isinstance(items, list) else []


def create(state: dict, name: str, scope: str) -> tuple[dict, str | None, list[str]]:
    """(new api section, token, errors)."""
    errors = []
    name = name.strip()
    if not LABEL_RE.fullmatch(name):
        errors.append("Name must be 1–40 characters")
    if scope not in SCOPES:
        errors.append("Pick a scope")
    items = tokens(state)
    if any(t.get("name") == name for t in items):
        errors.append(f"A token named {name} already exists")
    if len(items) >= MAX_TOKENS:
        errors.append(f"At most {MAX_TOKENS} tokens")
    if errors:
        return {"tokens": items}, None, errors
    token = PREFIX + secrets.token_urlsafe(32)
    new_id = max((t.get("id", 0) for t in items), default=0) + 1
    items.append({"id": new_id, "name": name, "scope": scope, "hash": _hash(token), "created": int(time.time())})
    return {"tokens": items}, token, []


def authenticate(state: dict, header: str | None, need: str) -> tuple[dict | None, str | None]:
    """(token entry, error) for an "Authorization: Bearer ..." header."""
    if not header or not header.startswith("Bearer "):
        return None, "missing bearer token"
    presented = _hash(header.removeprefix("Bearer ").strip())
    match = None
    for t in tokens(state):  # compare every hash: timing doesn't tell which one is close
        if secrets.compare_digest(str(t.get("hash", "")), presented):
            match = t
    if match is None:
        return None, "invalid token"
    if need not in SCOPES.get(match.get("scope"), ()):
        return None, f"this token's scope ({match.get('scope')}) doesn't allow {need}"
    return match, None


def usage(state_dir: Path) -> dict:
    return read_json(state_dir / "api-usage.json") or {}


def record_use(state_dir: Path, token_id: int) -> None:
    path = state_dir / "api-usage.json"
    data = usage(state_dir)
    data[str(token_id)] = int(time.time())
    tmp = path.with_name(".api-usage.json.tmp")
    tmp.write_text(json.dumps(data) + "\n")
    os.replace(tmp, path)
