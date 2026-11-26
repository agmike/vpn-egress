"""Notifications through Apprise (Telegram, ntfy, email, Discord, …).

state.json "notify": {"urls": ["tgram://…", "ntfy://…"]}

The panel checks the warnings once a minute (Status page and /api/status
show the same ones). Each warning has a key (what it is about) and a stage
(how bad: an expiring config goes 30 → 7 → 1 days → expired; traffic goes
projected → 80% → 100%). A message goes out when a warning reaches a new
stage and when it clears, each only after two checks in a row, so a
one-minute blip stays quiet. What was sent is kept in notify-state.json, so
a restart doesn't send it all again.

The URLs hold the services' tokens: the panel shows them masked.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import apprise

from .state import read_json

MAX_URLS = 10
CONFIRM = 2  # checks in a row before a change is sent


def urls(state: dict) -> list[str]:
    section = state.get("notify")
    items = section.get("urls") if isinstance(section, dict) else None
    return [u for u in items if isinstance(u, str)] if isinstance(items, list) else []


def describe(url: str) -> dict:
    """Service name and the URL with its secrets masked."""
    try:
        plugin = apprise.Apprise.instantiate(url)
    except Exception:  # a URL from an older Apprise, say
        plugin = None
    if not plugin:
        return {"service": "unknown", "masked": url.split("://", 1)[0] + "://…"}
    return {"service": str(plugin.service_name), "masked": plugin.url(privacy=True).split("?", 1)[0]}


def valid(url: str) -> bool:
    return bool(url) and len(url) <= 2000 and apprise.Apprise().add(url)


def send(targets: list[str], title: str, body: str) -> list[bool]:
    """Send to each target separately (one failing doesn't stop the rest)."""
    results = []
    for url in targets:
        a = apprise.Apprise()
        results.append(bool(a.add(url) and a.notify(title=title, body=body)))
    return results


class Notifier:
    def __init__(self, state_file: Path, sender: Callable[[str, str], object]):
        self.state_file = state_file
        self.sender = sender  # (title, body) -> anything
        self.data = read_json(state_file) or {}

    def check(self, warnings: list[dict]) -> list[tuple[str, str]]:
        """Compare with what was sent; send and return the (title, body) of changes."""
        sent = self.data.setdefault("sent", {})
        streak = self.data.setdefault("streak", {})  # key -> [stage or None, count]
        now = {w["key"]: w for w in warnings if w.get("key")}
        messages = []
        for key in set(now) | set(sent) | set(streak):
            w = now.get(key)
            stage = w["stage"] if w else None
            if stage == (sent.get(key) or {}).get("stage"):
                streak.pop(key, None)  # nothing new
                continue
            seen = streak.get(key)
            count = seen[1] + 1 if seen and seen[0] == stage else 1
            if count < CONFIRM:
                streak[key] = [stage, count]
                continue
            streak.pop(key, None)
            if w:
                sent[key] = {"stage": stage, "text": w["text"], "resolved": w.get("resolved")}
                icon = "⛔" if w["level"] == "bad" else "⚠️"
                headline = w["text"].split(". ", 1)[0].rstrip(".")
                messages.append((f"{icon} Egress: {headline}", w["text"]))
            else:
                old = sent.pop(key)
                done = old.get("resolved") or f"Resolved: {old.get('text', key)}"
                messages.append((f"✅ Egress: {done}", done))
        for title, body in messages:
            self.sender(title, body)
        self._save()
        return messages

    def _save(self) -> None:
        tmp = self.state_file.with_name("." + self.state_file.name + ".tmp")
        tmp.write_text(json.dumps(self.data) + "\n")
        os.replace(tmp, self.state_file)
