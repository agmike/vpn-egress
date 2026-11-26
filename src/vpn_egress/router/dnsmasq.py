"""dnsmasq as a child process: DNS for the pipe, blocklists, list sets."""

from __future__ import annotations

import signal
import subprocess
import sys
import threading
from collections.abc import Callable

from .config import Config


def render(cfg: Config, log_queries: bool = False) -> str:
    run = cfg.run_dir
    lines = [
        "# Written by vpn-egress.",
        "keep-in-foreground",
        "log-facility=-",
        *(["log-queries=extra"] if log_queries else []),
        "pid-file=",
        f"interface={cfg.pipe_iface}",
        "except-interface=lo",
        "bind-dynamic",
        "no-resolv",
        "no-hosts",
        *(f"server={u}" for u in cfg.dns_upstreams),
        f"cache-size={cfg.dns_cache_size}",
        "use-stale-cache",
        "domain-needed",
        "bogus-priv",
        # Lists resolved through their exit (re-read on SIGHUP).
        f"servers-file={run / 'servers.conf'}",
        # nftset= lines for list domains (needs a restart when they change).
        f"conf-file={run / 'lists.conf'}",
        f"conf-file={cfg.data_dir / 'blocklist.conf'}",
    ]
    return "\n".join(lines) + "\n"


class Dnsmasq:
    def __init__(self, cfg: Config, on_line: Callable[[str], bool] | None = None):
        """on_line: gets each log line (the query log when set); lines it
        doesn't take go to the router's own log."""
        self.cfg = cfg
        self.on_line = on_line
        self.conf = cfg.run_dir / "dnsmasq.conf"
        self.proc: subprocess.Popen | None = None

    def prepare(self) -> None:
        # dnsmasq drops to "nobody" and re-reads the servers-file on SIGHUP,
        # so its files must stay readable (they hold no secrets).
        self.cfg.run_dir.mkdir(parents=True, exist_ok=True)
        for d in (self.cfg.data_dir, self.cfg.run_dir):
            d.chmod(0o755)
        self.conf.write_text(render(self.cfg, log_queries=self.on_line is not None))
        for name in ("servers.conf", "lists.conf"):
            path = self.cfg.run_dir / name
            if not path.exists():
                path.write_text("")
        blocklist = self.cfg.data_dir / "blocklist.conf"
        if not blocklist.exists():
            blocklist.write_text("")

    def test(self) -> str | None:
        res = subprocess.run(["dnsmasq", "--test", f"--conf-file={self.conf}"], capture_output=True, text=True)
        return None if res.returncode == 0 else (res.stderr or res.stdout).strip()

    def start(self) -> None:
        if self.alive():
            return
        if self.on_line is None:
            self.proc = subprocess.Popen(["dnsmasq", f"--conf-file={self.conf}"], stdout=sys.stdout, stderr=sys.stderr)
            return
        self.proc = subprocess.Popen(
            ["dnsmasq", f"--conf-file={self.conf}"],
            stdout=sys.stdout,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            bufsize=1,
        )
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def _read(self, proc: subprocess.Popen) -> None:
        for line in proc.stderr:
            try:
                taken = self.on_line(line)
            except Exception:  # a parsing bug must not stop dnsmasq's output
                taken = False
            if not taken:
                sys.stderr.write(line)
                sys.stderr.flush()

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.proc = None

    def restart(self) -> None:
        self.stop()
        self.start()

    def reload(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGHUP)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None
