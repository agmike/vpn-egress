"""Exit monitoring and fallback servers.

Every SAMPLE seconds, for each enabled exit: a few pings through the tunnel
(IPv4, and IPv6 if the exit has it) for latency and packet loss, and the
tunnel's byte counters for the traffic rate. Speed is only measured from
real traffic (a quiet exit isn't a slow one), so only pings judge health.

Samples go into 5-minute buckets kept for 7 days, per exit and server; the
usual latency is the median of those buckets. An exit is degraded when, over
the last 5 minutes:
  - it had no handshake for 3 minutes, or every IPv4 ping was lost (down)
  - IPv4 packet loss averaged LOSS_LIMIT% or more
  - IPv4 latency was over twice its usual (and at least 100 ms more)
  - IPv6 (if the exit has it) lost every ping while IPv4 worked

With fallback on (exit "fallback": {"enabled", "provider", "country",
"ipv6"}), a degraded exit moves to a listed server in that country (same
key, another endpoint; servers.py), and on to the next if that one degrades
too. After RETURN_AFTER on a fallback server it goes back to its main
server, but only while idle, so a switch doesn't cut connections in use.
The panel can also switch by hand. Where each exit is: exit-servers.json in
the data directory; what the panel shows: exit-stats.json in the state
directory.
"""

from __future__ import annotations

import json
import re
import statistics
import subprocess
import threading
import time
from collections import deque
from pathlib import Path

from .servers import ServerList
from .system import run, write_json

SAMPLE = 30
WINDOW = 10  # samples: 5 minutes
BUCKET = 300
KEEP = 7 * 86400
GRACE = 180  # after a switch, let the new server settle before judging it
LOSS_LIMIT = 20
RETURN_AFTER = 6 * 3600
IDLE_RATE = 2000  # bytes/s in both directions together: nobody is using the exit
RETRY_AFTER = 6 * 3600  # a server that degraded is skipped this long
PING4, PING6 = "1.1.1.1", "2606:4700:4700::1111"
METRICS = ("rtt4", "loss4", "rtt6", "loss6")

LOSS_RE = re.compile(r"([0-9.]+)% packet loss")
RTT_RE = re.compile(r"= [0-9.]+/([0-9.]+)/")


def ping(iface: str, family: int) -> tuple[float, float | None]:
    """(loss %, average rtt in ms) of 5 pings through the interface."""
    target = PING4 if family == 4 else PING6
    try:
        res = subprocess.run(
            ["ping", f"-{family}", "-n", "-q", "-c", "5", "-i", "0.2", "-W", "2", "-I", iface, target],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 100.0, None
    loss = LOSS_RE.search(res.stdout)
    rtt = RTT_RE.search(res.stdout)
    return (float(loss.group(1)) if loss else 100.0), (float(rtt.group(1)) if rtt else None)


def transfer(iface: str) -> tuple[int, int] | None:
    out = run("wg", "show", iface, "transfer", check=False).stdout.split()
    return (int(out[1]), int(out[2])) if len(out) >= 3 else None


def handshake_age(iface: str) -> int | None:
    out = run("wg", "show", iface, "latest-handshakes", check=False).stdout.split()
    return int(time.time()) - int(out[1]) if len(out) >= 2 and out[1] != "0" else None


def _mean(values) -> float | None:
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 1) if values else None


class Stats:
    """One exit on one server: the last samples, and 5-minute buckets."""

    def __init__(self, buckets: list | None = None):
        self.buckets: list[dict] = buckets or []
        self.recent: deque = deque(maxlen=WINDOW)

    def add(self, s: dict) -> None:
        self.recent.append(s)
        start = int(s["t"] // BUCKET * BUCKET)
        if not self.buckets or self.buckets[-1]["t"] != start:
            self.buckets.append({"t": start, "peak_rx": 0, "peak_tx": 0, **{m: [0.0, 0] for m in METRICS}})
            while self.buckets and self.buckets[0]["t"] < s["t"] - KEEP:
                self.buckets.pop(0)
        b = self.buckets[-1]
        for m in METRICS:
            if s.get(m) is not None:
                b[m] = [b[m][0] + s[m], b[m][1] + 1]
        b["peak_rx"] = max(b["peak_rx"], s.get("rate_rx") or 0)
        b["peak_tx"] = max(b["peak_tx"], s.get("rate_tx") or 0)

    def usual(self, metric: str, now: float) -> float | None:
        """Median of the bucket means, not counting the last 5 minutes."""
        values = [b[metric][0] / b[metric][1] for b in self.buckets if b[metric][1] and b["t"] < now - BUCKET]
        return round(statistics.median(values), 1) if len(values) >= 12 else None  # an hour of data

    def summary(self, now: float) -> dict:
        r = list(self.recent)
        day = [b for b in self.buckets if b["t"] >= now - 86400]
        return {
            "now": {m: _mean(s.get(m) for s in r) for m in METRICS}
            | {"rate_rx": r[-1].get("rate_rx") if r else None, "rate_tx": r[-1].get("rate_tx") if r else None},
            "usual": {m: self.usual(m, now) for m in METRICS},
            "peak_24h": {
                "rx": max((b["peak_rx"] for b in day), default=0),
                "tx": max((b["peak_tx"] for b in day), default=0),
            },
            "peak_7d": {
                "rx": max((b["peak_rx"] for b in self.buckets), default=0),
                "tx": max((b["peak_tx"] for b in self.buckets), default=0),
            },
            "samples": len(r),
        }


def degraded(stats: Stats, has_v6: bool, handshake: int | None, now: float) -> str | None:
    """Why the exit counts as degraded over the last 5 minutes, or None."""
    r = list(stats.recent)
    if handshake is None or handshake > 180:
        return "down: no handshake for 3 minutes"
    if len(r) < WINDOW:
        return None  # not enough samples yet (or right after a switch)
    loss4 = _mean(s.get("loss4") for s in r)
    if loss4 is not None and loss4 >= 100:
        return "down: every IPv4 ping lost"
    if loss4 is not None and loss4 >= LOSS_LIMIT:
        return f"IPv4 packet loss {loss4:.0f}%"
    rtt4, usual = _mean(s.get("rtt4") for s in r), stats.usual("rtt4", now)
    if rtt4 is not None and usual is not None and rtt4 > max(2 * usual, usual + 100):
        return f"IPv4 latency {rtt4:.0f} ms (usually {usual:.0f} ms)"
    if has_v6 and all((s.get("loss6") or 0) >= 100 for s in r) and (loss4 or 0) < LOSS_LIMIT:
        return "IPv6 not working"
    return None


class ExitMonitor:
    def __init__(self, data_file: Path, stats_file: Path, uid: int, servers: ServerList):
        self.data_file, self.stats_file = data_file, stats_file
        self.uid, self.servers = uid, servers
        self.lock = threading.Lock()
        saved = _read(data_file)
        self.where: dict[str, dict] = saved.get("where", {})  # exit id -> {"server": {...} | None, "since", "reason"}
        self.failed: dict[str, dict[str, float]] = saved.get("failed", {})  # exit id -> {server name: when}
        self.stats: dict[str, Stats] = {k: Stats(v) for k, v in saved.get("stats", {}).items()}
        self.last_counters: dict[str, tuple[float, int, int]] = {}
        self.exits: dict[int, dict] = {}  # from apply: the validated exits
        self.health: dict[str, str | None] = {}
        self.switched = threading.Event()  # set when a switch needs an apply

    # --- what apply() uses -----------------------------------------------------------

    def set_exits(self, exits: dict[int, dict]) -> None:
        with self.lock:
            self.exits = exits
            for key in list(self.where):
                ex = exits.get(int(key))
                if ex is None:
                    self.where.pop(key)  # the exit is gone
                elif self.where[key].get("server") and not (ex.get("fallback") or {}).get("enabled"):
                    self._go(int(key), None, "fallback turned off", time.time())

    def server_for(self, eid: int) -> dict | None:
        """The fallback server an exit is on, or None for its main one."""
        with self.lock:
            return (self.where.get(str(eid)) or {}).get("server")

    # --- sampling -----------------------------------------------------------------------

    def sample(self) -> None:
        with self.lock:
            exits = {eid: ex for eid, ex in self.exits.items() if ex.get("enabled")}
        now = time.time()
        results: dict[int, dict] = {}

        def one(eid: int, ex: dict) -> None:
            iface = f"egx{eid}"
            loss4, rtt4 = ping(iface, 4)
            loss6, rtt6 = ping(iface, 6) if ex.get("address6") else (None, None)
            s = {"t": now, "loss4": loss4, "rtt4": rtt4, "loss6": loss6, "rtt6": rtt6}
            got = transfer(iface)
            last = self.last_counters.get(iface)
            if got and last and got[0] >= last[1] and got[1] >= last[2] and now > last[0]:
                s["rate_rx"] = int((got[0] - last[1]) / (now - last[0]))
                s["rate_tx"] = int((got[1] - last[2]) / (now - last[0]))
            if got:
                self.last_counters[iface] = (now, *got)
            s["handshake"] = handshake_age(iface)
            results[eid] = s

        threads = [threading.Thread(target=one, args=item, daemon=True) for item in exits.items()]
        for t in threads:
            t.start()
        for t in threads:
            t.join(25)
        with self.lock:
            for eid, s in results.items():
                self.stats.setdefault(self._key_locked(eid), Stats()).add(s)
        self.evaluate(results, now)
        self.publish(now)

    def _key_locked(self, eid: int) -> str:
        server = (self.where.get(str(eid)) or {}).get("server")
        return f"{eid}:{server['name'] if server else 'main'}"

    # --- deciding -----------------------------------------------------------------------

    def evaluate(self, results: dict[int, dict], now: float) -> None:
        with self.lock:
            for eid, s in results.items():
                ex = self.exits.get(eid) or {}
                key = str(eid)
                here = self.where.get(key) or {}
                stats = self.stats.get(self._key_locked(eid))
                settling = now - here.get("since", 0) < GRACE
                has_v6 = bool(ex.get("address6"))
                why = None if settling or stats is None else degraded(stats, has_v6, s.get("handshake"), now)
                self.health[key] = why
                fb = ex.get("fallback") or {}
                if not fb.get("enabled"):
                    continue
                if why:
                    self._move(eid, why, now)
                elif here.get("server") and now - here.get("since", now) >= RETURN_AFTER and self._idle(stats):
                    self._go(eid, None, "back to the main server (on a fallback for 6 hours, exit idle)", now)

    @staticmethod
    def _idle(stats: Stats | None) -> bool:
        r = list(stats.recent) if stats else []
        return bool(r) and all((x.get("rate_rx") or 0) + (x.get("rate_tx") or 0) < IDLE_RATE for x in r)

    def _move(self, eid: int, why: str, now: float) -> bool:
        """To the next fallback server (lock held)."""
        ex = self.exits.get(eid) or {}
        fb = ex.get("fallback") or {}
        key = str(eid)
        here = self.where.get(key) or {}
        failed = {n: t for n, t in self.failed.get(key, {}).items() if now - t < RETRY_AFTER}
        current = (here.get("server") or {}).get("name", "main")
        failed[current] = now
        self.failed[key] = failed
        exclude = set(failed) | {ex.get("endpoint", "")}
        provider, country = fb.get("provider", "protonvpn"), fb.get("country", "")
        candidates = self.servers.candidates(provider, country, bool(fb.get("ipv6")), exclude)
        if not candidates:
            # Nothing left to try: the main server (it may have recovered), or stay on it.
            if here.get("server"):
                return self._go(eid, None, f"{why}; no other listed server left, back to main", now)
            return False
        return self._go(eid, candidates[0], why, now)

    def _go(self, eid: int, server: dict | None, why: str, now: float) -> bool:
        key = str(eid)
        self.where[key] = {"server": server, "since": now, "reason": why}
        self.stats.get(f"{eid}:{server['name'] if server else 'main'}", Stats()).recent.clear()
        self.switched.set()
        self._save()
        return True

    # --- from the panel ---------------------------------------------------------------

    def command(self, eid: int, target: str) -> dict:
        now = time.time()
        with self.lock:
            ex = self.exits.get(eid)
            if ex is None:
                return {"ok": False, "message": "no such exit"}
            if target == "main":
                if not (self.where.get(str(eid)) or {}).get("server"):
                    return {"ok": True, "message": "already on the main server"}
                self._go(eid, None, "switched to the main server by hand", now)
                return {"ok": True, "message": "switching to the main server"}
            if not (ex.get("fallback") or {}).get("country"):
                return {"ok": False, "message": "set a fallback country first"}
            if self._move(eid, "switched by hand", now):
                server = self.where[str(eid)]["server"]
                return {"ok": True, "message": f"switching to {server['name'] if server else 'the main server'}"}
            return {"ok": False, "message": "no other listed server in that country"}

    # --- persistence and status -----------------------------------------------------------

    def _save(self) -> None:
        data = {"where": self.where, "failed": self.failed, "stats": {k: v.buckets for k, v in self.stats.items()}}
        tmp = self.data_file.with_name("." + self.data_file.name + ".tmp")
        tmp.write_text(json.dumps(data))
        tmp.replace(self.data_file)

    def publish(self, now: float) -> None:
        with self.lock:
            out = {"updated": int(now), "exits": {}}
            for eid in self.exits:
                here = self.where.get(str(eid)) or {}
                server = here.get("server")
                stats = self.stats.get(self._key_locked(eid))
                out["exits"][str(eid)] = {
                    "server": {k: server[k] for k in ("name", "city", "country", "endpoint")} if server else None,
                    "since": here.get("since"),
                    "reason": here.get("reason"),
                    "degraded": self.health.get(str(eid)),
                    "stats": stats.summary(now) if stats else None,
                }
            if int(now) % BUCKET < SAMPLE:  # the buckets on disk every 5 minutes
                self._save()
        write_json(self.stats_file, out, self.uid)


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}
