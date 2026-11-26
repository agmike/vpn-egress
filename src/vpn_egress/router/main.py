"""vpn-egress-router: the privileged half. Runs on the host network with
CAP_NET_ADMIN; applies the panel's state, keeps dnsmasq running, refreshes
blocklists."""

from __future__ import annotations

import json
import signal
import sys
import threading
import time
import traceback
from pathlib import Path

from . import blocklists, firewall, live, lookup, traffic
from . import pipe as pipe_mod
from .apply import StateError, apply, required_sources, validate
from .config import Config, ConfigError
from .dnsmasq import Dnsmasq
from .sources import SourceCache
from .system import nft_apply

POLL = 2  # seconds between checks of the state file
TRAFFIC_INTERVAL = 60
# After a change, exits that are new or got a new config need a moment for
# their first handshake: re-check soon instead of at the next interval
# (until then they count as down, and a kill switch blocks their lists).
FAST_WINDOW = 60
FAST_INTERVAL = 3


def log(msg: str) -> None:
    print(f"vpn-egress-router: {msg}", flush=True)


def health(cfg: Config, proc: Path = Path("/proc")) -> str | None:
    """For the container's HEALTHCHECK: None when healthy, else why not."""
    try:
        age = time.time() - (cfg.state_dir / "status.json").stat().st_mtime
    except FileNotFoundError:
        return "no status written yet"
    if age > 3 * cfg.apply_interval + 30:
        return f"status is {int(age)} s old: the apply loop is stuck"
    for comm in proc.glob("[0-9]*/comm"):
        try:
            if comm.read_text().strip() == "dnsmasq":
                return None
        except OSError:
            continue
    return "dnsmasq is not running"


def main() -> int:
    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        log(f"config error: {exc}")
        return 2
    if sys.argv[1:] == ["--health"]:
        problem = health(cfg)
        print(problem or "ok")
        return 1 if problem else 0
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    state_file = cfg.state_dir / "state.json"

    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(True))
    signal.signal(signal.SIGINT, lambda *_: stop.append(True))

    live_log = live.LiveLog(cfg.pipe_addresses) if cfg.live_log else None
    dns = Dnsmasq(cfg, on_line=live_log.feed_dns if live_log else None)
    conntrack = live.Conntrack(live_log) if live_log else None
    publisher = live.Publisher(live_log, cfg.state_dir, cfg.state_uid) if live_log else None
    conntrack_retry = [0.0]

    def keep_conntrack() -> None:
        if conntrack is None or conntrack.alive() or time.monotonic() < conntrack_retry[0]:
            return
        err = conntrack.start()
        if err:
            log(f"live log: {err}; connections are not shown (retrying in 5 min)")
            conntrack_retry[0] = time.monotonic() + 300
        else:
            conntrack_retry[0] = time.monotonic() + 30  # if it exits right away, don't spin

    dns.prepare()
    cache = SourceCache(cfg.data_dir / "sources", cfg.geoip_url, cfg.asn_url)

    dbs = lookup.Databases(cfg.data_dir / "lookup", {"country": cfg.country_db_url, "asn": cfg.asn_db_url})
    lookup_server = None
    if live_log:
        try:
            lookup_server = lookup.serve(
                lookup.Lookup(cfg, cache, dbs, live_log), cfg.state_dir / "lookup.sock", cfg.state_uid
            )
        except OSError as exc:
            log(f"lookup: {exc}")

    def refresh_dbs(max_age: float) -> None:
        def work() -> None:
            for err in dbs.refresh(max_age):
                log(f"lookup: {err}")

        if live_log:  # in the background: large downloads must not hold up routing
            threading.Thread(target=work, daemon=True).start()

    def refresh_sources(max_age: float) -> None:
        """Download GeoIP/ASN/URL sources the lists use (missing ones only
        with max_age=inf)."""
        try:
            raw = json.loads(state_file.read_text()) if state_file.exists() else {}
            cache.refresh(required_sources(validate(raw)), max_age)
        except (StateError, ValueError, OSError) as exc:
            log(f"sources: {exc}")

    meter = traffic.Meter(
        cfg.data_dir / "traffic.json",
        cfg.state_dir / "traffic.json",
        cfg.traffic_iface,
        cfg.traffic_allowance,
        cfg.state_uid,
    )
    meter_error: list[str | None] = [None]

    def do_traffic() -> None:
        try:
            err = meter.sample()
        except Exception as exc:  # never stop routing over the meter
            err = f"{type(exc).__name__}: {exc}"
        if err != meter_error[0]:
            log(f"traffic: {err}" if err else "traffic: counting")
            meter_error[0] = err

    nft_apply(firewall.render(cfg))
    last_routes: list[str] = []
    last_pipe: list[str] = []

    exits_waiting = [False]

    def do_apply(reason: str) -> None:
        try:
            status = apply(cfg, dns, last_routes, cache, last_pipe, live_log)
            if status["error"]:
                log(f"apply ({reason}): {status['error']}")
            exits_waiting[0] = any(e["enabled"] and not e["up"] for e in status["exits"])
        except Exception:  # keep running; the next tick retries
            log(f"apply ({reason}) failed:\n{traceback.format_exc()}")

    def do_blocklists(quick: bool) -> None:
        try:
            status = blocklists.refresh(cfg, dns, quick)
            msg = f"blocklists ({status['mode']}): {status['blocked']} names"
            if status["error"]:
                msg += f", error: {status['error']}"
            log(msg)
        except Exception:
            log(f"blocklists failed:\n{traceback.format_exc()}")

    # Sets must exist before dnsmasq starts filling them.
    refresh_dbs(max_age=cfg.source_interval)
    refresh_sources(max_age=cfg.source_interval)
    do_apply("start")
    dns.start()
    blocklist_file = blocklists.blocklist_path(cfg)
    stale = not blocklist_file.exists() or time.time() - blocklist_file.stat().st_mtime > cfg.blocklist_interval
    do_blocklists(quick=not stale)
    now = time.monotonic()
    last_apply = last_full = last_sources = last_traffic = now
    fast_until = now + FAST_WINDOW
    do_traffic()
    last_mtime = state_file.stat().st_mtime if state_file.exists() else None

    while not stop:
        time.sleep(POLL)
        keep_conntrack()
        if publisher:
            try:
                publisher.tick()
            except OSError as exc:
                log(f"live log: {exc}")
        if not dns.alive():
            log("dnsmasq exited; restarting")
            dns.start()
        mtime = state_file.stat().st_mtime if state_file.exists() else None
        now = time.monotonic()
        if cfg.pipe_manage and last_pipe and not pipe_mod.exists(cfg):
            log("pipe interface missing; recreating")
            last_pipe.clear()
            do_apply("pipe missing")
            last_apply = now
        if mtime != last_mtime:
            last_mtime = mtime
            refresh_sources(max_age=float("inf"))  # only what's missing
            do_apply("state changed")
            do_blocklists(quick=True)
            last_apply = now
            fast_until = now + FAST_WINDOW
        elif exits_waiting[0] and now < fast_until and now - last_apply >= FAST_INTERVAL:
            do_apply("waiting for exits")
            last_apply = now
        elif now - last_apply >= cfg.apply_interval:
            do_apply("interval")
            last_apply = now
        if now - last_traffic >= TRAFFIC_INTERVAL:
            do_traffic()
            last_traffic = now
        if now - last_full >= cfg.blocklist_interval:
            do_blocklists(quick=False)
            last_full = now
        if now - last_sources >= cfg.source_interval:
            refresh_dbs(max_age=cfg.source_interval)
            refresh_sources(max_age=cfg.source_interval)
            do_apply("sources refreshed")
            last_sources = last_apply = now

    log("stopping")
    if conntrack:
        conntrack.stop()
    if lookup_server:
        lookup_server.shutdown()
        (cfg.state_dir / "lookup.sock").unlink(missing_ok=True)
    if publisher:
        (cfg.state_dir / "live.json").unlink(missing_ok=True)
    do_traffic()
    dns.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
