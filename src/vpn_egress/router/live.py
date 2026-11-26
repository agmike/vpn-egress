"""Live log: recent DNS queries and connections from the pipe.

Two sources, both kept in memory only (the last MAX_ITEMS of each):
  - dnsmasq's query log (log-queries=extra), read from its stderr: one
    record per query with its client, answers and result (answered, cached,
    blocked, NXDOMAIN), and the routing list that claims the name
  - conntrack events for new connections from the pipe (ct mark bit
    0x01000000, see firewall.py): the list that routed it (ct mark low 16
    bits), where it left (the source address NAT gave it: an exit's or this
    server's), and the name it was looked up as (from the DNS answers)

The records are written to live.json in the state directory only while the
panel's Live page is open (it touches live-watch every few seconds), and
deleted when nobody watches. EGRESS_LIVE_LOG=false turns all of it off.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

from .system import write_json

MAX_ITEMS = 1000
PUBLISH = 400  # newest records of each kind written for the panel
MAX_NAMES = 20000  # address -> name cache
WATCH_FRESH = 15  # seconds: the panel touches live-watch while the page is open
PIPE_BIT = 0x01000000

DNS_RE = re.compile(r"^dnsmasq\[\d+\]: (\d+) ([0-9A-Fa-f:.]+)/\d+ (\S+) (\S+)(?: (.*))?$")
CONFIG_BLOCKED = {"NXDOMAIN", "NODATA", "NODATA-IPv4", "NODATA-IPv6", "0.0.0.0", "::"}


def _ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


class LiveLog:
    def __init__(self, pipe_addresses: tuple = ()):
        self.dns: deque[dict] = deque(maxlen=MAX_ITEMS)
        self.conns: deque[dict] = deque(maxlen=MAX_ITEMS)
        self.pending: dict[str, dict] = {}
        self.names: OrderedDict[str, str] = OrderedDict()
        self.lock = threading.Lock()
        self.server_ips = {str(a.ip) for a in pipe_addresses}
        self.server_nets = [a.network for a in pipe_addresses]
        # Set by apply(): {"domains": {name: list id}, "exit_addrs": {ip: exit id}}
        self.view: dict = {"domains": {}, "exit_addrs": {}}
        self.changed = 0  # bumps on every new record

    # --- DNS ----------------------------------------------------------------------

    def list_for(self, name: str) -> int | None:
        domains = self.view.get("domains") or {}
        labels = name.lower().rstrip(".").split(".")
        for k in range(len(labels)):
            lid = domains.get(".".join(labels[k:]))
            if lid is not None:
                return lid
        return None

    def feed_dns(self, line: str) -> bool:
        """Take a dnsmasq log line; False if it isn't part of the query log."""
        m = DNS_RE.match(line.strip())
        if not m:
            return False
        serial, client, verb, name, rest = m.groups()
        rest = rest or ""
        with self.lock:
            if verb.startswith("query["):
                rec = {
                    "t": round(time.time(), 3),
                    "client": client,
                    "type": verb[6:-1],
                    "name": name,
                    "result": "pending",
                    "server": None,
                    "answers": [],
                    "list": self.list_for(name),
                }
                self.pending[serial] = rec
                if len(self.pending) > 2 * MAX_ITEMS:  # queries that never got an answer
                    for key in list(self.pending)[:MAX_ITEMS]:
                        self.pending.pop(key)
                self.dns.append(rec)
                self.changed += 1
                return True
            rec = self.pending.get(serial)
            if rec is None:
                return True
            value = rest.removeprefix("is ").removeprefix("to ").strip()
            if verb == "forwarded":
                rec["server"] = value
                rec["result"] = "forwarded"
            elif verb in ("reply", "cached", "config"):
                if verb == "config" and value in CONFIG_BLOCKED:
                    rec["result"] = "blocked"
                elif value in ("NXDOMAIN", "NODATA", "NODATA-IPv4", "NODATA-IPv6", "SERVFAIL", "REFUSED"):
                    rec["result"] = value.lower().split("-")[0]
                else:
                    rec["result"] = "cached" if verb == "cached" else "answered" if verb == "reply" else "local"
                    if _ip(value) is not None and len(rec["answers"]) < 16:
                        rec["answers"].append(value)
                        self.names[value] = rec["name"]
                        self.names.move_to_end(value)
                        if len(self.names) > MAX_NAMES:
                            self.names.popitem(last=False)
            self.changed += 1
        return True

    # --- connections -----------------------------------------------------------------

    def feed_conn(self, line: str) -> None:
        if "[NEW]" not in line:
            return
        head, _, tail = line.partition("[NEW]")
        tokens = tail.split()
        if not tokens:
            return
        proto = tokens[0]
        orig: dict[str, str] = {}
        reply: dict[str, str] = {}
        mark = 0
        for tok in tokens[1:]:
            key, sep, value = tok.partition("=")
            if not sep:
                continue
            if key == "mark":
                mark = int(value) if value.isdigit() else 0
            elif key in ("src", "dst", "sport", "dport", "type"):
                (reply if key in orig else orig)[key] = value
        src, dst = orig.get("src"), orig.get("dst")
        if not src or not dst or reply.get("src") in self.server_ips:
            return  # to this server itself (DNS, the panel): not routed traffic
        dst_ip = _ip(dst)
        nets = self.server_nets + list(self.view.get("pipe_nets") or [])
        if dst_ip is not None and any(dst_ip in n for n in nets if n.version == dst_ip.version):
            via = "pipe"  # peer to peer
        else:
            via = (self.view.get("exit_addrs") or {}).get(reply.get("dst"), "direct")
        stamp = re.search(r"\[([0-9.]+)\]", head)
        lid = mark & 0xFFFF
        with self.lock:
            self.conns.append(
                {
                    "t": round(float(stamp.group(1)), 3) if stamp else round(time.time(), 3),
                    "proto": proto,
                    "client": src,
                    "dst": dst,
                    "port": int(orig["dport"]) if orig.get("dport", "").isdigit() else None,
                    "name": self.names.get(dst),
                    "list": lid or None,
                    "via": via,
                }
            )
            self.changed += 1

    # --- publishing ----------------------------------------------------------------

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "updated": int(time.time()),
                "dns": [dict(r, answers=list(r["answers"])) for r in list(self.dns)[-PUBLISH:]][::-1],
                "conns": [dict(r) for r in list(self.conns)[-PUBLISH:]][::-1],
            }


class Conntrack:
    """`conntrack -E` for new pipe connections, fed to a LiveLog."""

    def __init__(self, live: LiveLog):
        self.live = live
        self.proc: subprocess.Popen | None = None

    def start(self) -> str | None:
        if self.alive():
            return None
        try:
            self.proc = subprocess.Popen(
                ["conntrack", "-E", "-e", "NEW", "-o", "timestamp", "--mark", f"{PIPE_BIT:#x}/{PIPE_BIT:#x}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            return f"conntrack: {exc}"
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()
        return None

    def _read(self, proc: subprocess.Popen) -> None:
        for line in proc.stdout:
            if "[NEW]" in line:
                self.live.feed_conn(line)
            elif line.strip():
                print(f"conntrack: {line.strip()}", file=sys.stderr, flush=True)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.alive():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class Publisher:
    """Writes live.json while the panel watches, removes it after."""

    def __init__(self, live: LiveLog, state_dir: Path, uid: int):
        self.live, self.uid = live, uid
        self.watch, self.out = state_dir / "live-watch", state_dir / "live.json"
        self.written = -1

    def tick(self) -> None:
        try:
            watched = time.time() - self.watch.stat().st_mtime < WATCH_FRESH
        except FileNotFoundError:
            watched = False
        if watched:
            if self.live.changed != self.written or not self.out.exists():
                write_json(self.out, self.live.snapshot(), self.uid)
                self.written = self.live.changed
        elif self.out.exists():
            self.out.unlink(missing_ok=True)
            self.written = -1
