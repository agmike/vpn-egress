"""vpn-egress-router: the privileged half. Runs on the host network with
CAP_NET_ADMIN; applies the panel's state, keeps dnsmasq running, refreshes
blocklists."""

from __future__ import annotations

import json
import signal
import sys
import time
import traceback

from . import blocklists, firewall, traffic
from . import pipe as pipe_mod
from .apply import StateError, apply, required_sources, validate
from .config import Config, ConfigError
from .dnsmasq import Dnsmasq
from .sources import SourceCache
from .system import nft_apply

POLL = 2  # seconds between checks of the state file
TRAFFIC_INTERVAL = 60


def log(msg: str) -> None:
    print(f"vpn-egress-router: {msg}", flush=True)


def main() -> int:
    try:
        cfg = Config.from_env()
    except ConfigError as exc:
        log(f"config error: {exc}")
        return 2
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    state_file = cfg.state_dir / "state.json"

    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(True))
    signal.signal(signal.SIGINT, lambda *_: stop.append(True))

    dns = Dnsmasq(cfg)
    dns.prepare()
    cache = SourceCache(cfg.data_dir / "sources", cfg.geoip_url, cfg.asn_url)

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

    def do_apply(reason: str) -> None:
        try:
            status = apply(cfg, dns, last_routes, cache, last_pipe)
            if status["error"]:
                log(f"apply ({reason}): {status['error']}")
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
    refresh_sources(max_age=cfg.source_interval)
    do_apply("start")
    dns.start()
    blocklist_file = blocklists.blocklist_path(cfg)
    stale = not blocklist_file.exists() or time.time() - blocklist_file.stat().st_mtime > cfg.blocklist_interval
    do_blocklists(quick=not stale)
    now = time.monotonic()
    last_apply = last_full = last_sources = last_traffic = now
    do_traffic()
    last_mtime = state_file.stat().st_mtime if state_file.exists() else None

    while not stop:
        time.sleep(POLL)
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
            refresh_sources(max_age=cfg.source_interval)
            do_apply("sources refreshed")
            last_sources = last_apply = now

    log("stopping")
    do_traffic()
    dns.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
