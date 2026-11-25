"""vpn-egress-router: the privileged half. Runs on the host network with
CAP_NET_ADMIN; applies the panel's state, keeps dnsmasq running, refreshes
blocklists."""

from __future__ import annotations

import signal
import sys
import time
import traceback

from . import blocklists, firewall
from .apply import apply
from .config import Config, ConfigError
from .dnsmasq import Dnsmasq
from .system import nft_apply

POLL = 2  # seconds between checks of the state file


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
    nft_apply(firewall.render(cfg))
    last_routes: list[str] = []

    def do_apply(reason: str) -> None:
        try:
            status = apply(cfg, dns, last_routes)
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
    do_apply("start")
    dns.start()
    blocklist_file = blocklists.blocklist_path(cfg)
    stale = not blocklist_file.exists() or time.time() - blocklist_file.stat().st_mtime > cfg.blocklist_interval
    do_blocklists(quick=not stale)
    now = time.monotonic()
    last_apply = last_full = now
    last_mtime = state_file.stat().st_mtime if state_file.exists() else None

    while not stop:
        time.sleep(POLL)
        if not dns.alive():
            log("dnsmasq exited; restarting")
            dns.start()
        mtime = state_file.stat().st_mtime if state_file.exists() else None
        now = time.monotonic()
        if mtime != last_mtime:
            last_mtime = mtime
            do_apply("state changed")
            do_blocklists(quick=True)
            last_apply = now
        elif now - last_apply >= cfg.apply_interval:
            do_apply("interval")
            last_apply = now
        if now - last_full >= cfg.blocklist_interval:
            do_blocklists(quick=False)
            last_full = now

    log("stopping")
    dns.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
