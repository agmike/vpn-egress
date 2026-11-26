"""Traffic meter: bytes through the uplink, per calendar month (UTC).

Cloud providers bill outbound transfer per month (OCI: 10 TB free), and
interface counters reset on reboot, so totals are kept in the data
directory (traffic.json) and advanced by the counter deltas:

  {"month": "2026-11", "tx": 123, "rx": 456, "since": 1764000000,
   "last": {"iface": "eth0", "boot": "<boot id>", "tx": 789, "rx": 1011},
   "days": {"2026-11-26": [tx, rx]}, "months": {"2026-10": [tx, rx]}}

"since" is when counting started in this month (later than the 1st on the
first run, unless the host booted this month: then counting starts at boot,
from the counters as they are). A summary for the panel goes to
traffic.json in the state directory.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from pathlib import Path

from .system import ip_json, write_json

KEEP_DAYS = 62
KEEP_MONTHS = 24


def default_iface() -> str | None:
    for fam in ("-4", "-6"):
        for r in ip_json(fam, "route", "show", "default"):
            if r.get("dev"):
                return r["dev"]
    return None


def counters(iface: str) -> tuple[int, int] | None:
    try:
        stats = ip_json("-s", "link", "show", "dev", iface)[0]["stats64"]
        return int(stats["tx"]["bytes"]), int(stats["rx"]["bytes"])
    except (IndexError, KeyError, ValueError, OSError):
        return None


def boot_info() -> tuple[str, float]:
    """(boot id, boot time as a Unix timestamp)."""
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    return boot, time.time() - uptime


def _month(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m")


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d")


def _month_start(ts: float) -> float:
    d = datetime.fromtimestamp(ts, UTC)
    return datetime(d.year, d.month, 1, tzinfo=UTC).timestamp()


def advance(data: dict, iface: str, raw: tuple[int, int], boot: str, boot_time: float, now: float) -> dict:
    """Add the counter delta since the last sample to the totals (pure)."""
    data = dict(data) if isinstance(data, dict) else {}
    month = _month(now)
    if data.get("month") != month:
        if data.get("month"):
            months = dict(data.get("months") or {})
            months[data["month"]] = [data.get("tx", 0), data.get("rx", 0)]
            data["months"] = dict(sorted(months.items())[-KEEP_MONTHS:])
        data.update(month=month, tx=0, rx=0, since=now if data.get("month") is None else _month_start(now))
    last = data.get("last") or {}
    if not last:
        # First run: count from boot if the host booted this month.
        if boot_time >= _month_start(now):
            delta = raw
            data["since"] = boot_time
        else:
            delta = (0, 0)
    elif last.get("iface") != iface:
        delta = (0, 0)  # another interface: its counters are not ours
    elif last.get("boot") != boot or raw[0] < last.get("tx", 0) or raw[1] < last.get("rx", 0):
        delta = raw  # reboot or counter reset: everything since is new
    else:
        delta = (raw[0] - last["tx"], raw[1] - last["rx"])
    data["tx"] = data.get("tx", 0) + delta[0]
    data["rx"] = data.get("rx", 0) + delta[1]
    days = dict(data.get("days") or {})
    d = days.get(_day(now), [0, 0])
    days[_day(now)] = [d[0] + delta[0], d[1] + delta[1]]
    data["days"] = dict(sorted(days.items())[-KEEP_DAYS:])
    data["last"] = {"iface": iface, "boot": boot, "tx": raw[0], "rx": raw[1]}
    return data


def summary(data: dict, iface: str | None, allowance: int, now: float) -> dict:
    """What the panel shows."""
    start = _month_start(now)
    d = datetime.fromtimestamp(start, UTC)
    end = datetime(d.year + d.month // 12, d.month % 12 + 1, 1, tzinfo=UTC).timestamp()
    since = max(float(data.get("since") or now), start)
    counted = now - since
    tx = int(data.get("tx", 0))
    # Projection: the rate so far over the rest of the month (once there is a day of data).
    projected = int(tx + tx / counted * (end - now)) if counted >= 86400 else None
    return {
        "updated": int(now),
        "iface": iface,
        "month": data.get("month"),
        "since": int(since),
        "month_start": int(start),
        "tx": tx,
        "rx": int(data.get("rx", 0)),
        "allowance": allowance or None,
        "projected_tx": projected,
        "today": (data.get("days") or {}).get(_day(now), [0, 0]),
        "days": data.get("days") or {},
        "months": data.get("months") or {},
    }


class Meter:
    def __init__(self, data_file: Path, status_file: Path, iface: str, allowance: int, uid: int):
        self.data_file, self.status_file = data_file, status_file
        self.iface_setting, self.allowance, self.uid = iface, allowance, uid
        try:
            self.data = json.loads(data_file.read_text())
        except (OSError, ValueError):
            self.data = {}

    def sample(self) -> str | None:
        """Read the counters, save the totals and the summary. Returns an error."""
        now = time.time()
        iface = self.iface_setting or default_iface()
        raw = counters(iface) if iface else None
        if raw is None:
            return f"no counters for {iface or 'the default route interface'}"
        boot, boot_time = boot_info()
        self.data = advance(self.data, iface, raw, boot, boot_time, now)
        tmp = self.data_file.with_name("." + self.data_file.name + ".tmp")
        tmp.write_text(json.dumps(self.data) + "\n")
        tmp.replace(self.data_file)
        write_json(self.status_file, summary(self.data, iface, self.allowance, now), self.uid)
        return None
