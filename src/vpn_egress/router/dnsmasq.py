"""dnsmasq as a child process: DNS for the pipe, blocklists, list sets."""

from __future__ import annotations

import signal
import subprocess
import sys

from .config import Config


def render(cfg: Config) -> str:
    run = cfg.run_dir
    lines = [
        "# Written by vpn-egress.",
        "keep-in-foreground",
        "log-facility=-",
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
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.conf = cfg.run_dir / "dnsmasq.conf"
        self.proc: subprocess.Popen | None = None

    def prepare(self) -> None:
        # dnsmasq drops to "nobody" and re-reads the servers-file on SIGHUP,
        # so its files must stay readable (they hold no secrets).
        self.cfg.run_dir.mkdir(parents=True, exist_ok=True)
        for d in (self.cfg.data_dir, self.cfg.run_dir):
            d.chmod(0o755)
        self.conf.write_text(render(self.cfg))
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
        self.proc = subprocess.Popen(["dnsmasq", f"--conf-file={self.conf}"], stdout=sys.stdout, stderr=sys.stderr)

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
