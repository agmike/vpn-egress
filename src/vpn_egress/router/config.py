"""Router settings, all from environment variables."""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path

IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


class ConfigError(ValueError):
    pass


# MetaCubeX/meta-rules-dat: per-country and per-service GeoIP lists and
# per-ASN lists as plain CIDR text, updated daily.
GEOIP_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/{name}.list"
ASN_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/asn/{asn}.list"


def _template(value: str, field: str) -> str:
    if not value.startswith("https://") or field not in value:
        raise ConfigError(f"source URL templates must be https:// and contain {field}")
    return value


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    state_dir: Path
    data_dir: Path
    pipe_iface: str
    pipe_tool: str
    dns_upstreams: tuple[str, ...]
    dns_cache_size: int
    dns_redirect: bool
    block_dot: bool
    state_uid: int
    apply_interval: int
    blocklist_interval: int
    source_interval: int
    geoip_url: str
    asn_url: str

    @property
    def run_dir(self) -> Path:
        return self.data_dir / "run"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> Config:
        env = dict(os.environ if env is None else env)

        def get(name: str, default: str) -> str:
            return env.get(name, default).strip() or default

        pipe = get("EGRESS_PIPE_IFACE", "awg0")
        if not IFACE_RE.match(pipe):
            raise ConfigError(f"EGRESS_PIPE_IFACE: bad interface name {pipe!r}")
        tool = get("EGRESS_PIPE_TOOL", "awg")
        if tool not in ("awg", "wg"):
            raise ConfigError("EGRESS_PIPE_TOOL must be awg or wg")
        upstreams = []
        for u in get("EGRESS_DNS_UPSTREAMS", "9.9.9.9,149.112.112.112").split(","):
            try:
                upstreams.append(str(ipaddress.ip_address(u.strip())))
            except ValueError as exc:
                raise ConfigError(f"EGRESS_DNS_UPSTREAMS: {u!r} is not an IP address") from exc
        try:
            return cls(
                state_dir=Path(get("EGRESS_STATE_DIR", "/state")),
                data_dir=Path(get("EGRESS_DATA_DIR", "/data")),
                pipe_iface=pipe,
                pipe_tool=tool,
                dns_upstreams=tuple(upstreams),
                dns_cache_size=int(get("EGRESS_DNS_CACHE_SIZE", "10000")),
                dns_redirect=_bool(get("EGRESS_DNS_REDIRECT", "true")),
                block_dot=_bool(get("EGRESS_BLOCK_DOT", "true")),
                state_uid=int(get("EGRESS_STATE_UID", "10300")),
                apply_interval=int(get("EGRESS_APPLY_INTERVAL", "60")),
                blocklist_interval=int(get("EGRESS_BLOCKLIST_INTERVAL", "86400")),
                source_interval=int(get("EGRESS_SOURCE_INTERVAL", "86400")),
                geoip_url=_template(get("EGRESS_GEOIP_URL", GEOIP_URL), "{name}"),
                asn_url=_template(get("EGRESS_ASN_URL", ASN_URL), "{asn}"),
            )
        except ValueError as exc:
            raise ConfigError(f"bad numeric setting: {exc}") from exc
