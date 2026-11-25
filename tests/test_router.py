import base64
import os

import pytest

from vpn_egress.router import apply, blocklists, dnsmasq, firewall
from vpn_egress.router.config import Config, ConfigError


def key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def cfg(**env) -> Config:
    return Config.from_env({"EGRESS_STATE_DIR": "/s", "EGRESS_DATA_DIR": "/d", **env})


def state(**list_overrides):
    return {
        "exits": [
            {
                "id": 3,
                "name": "NL 1",
                "enabled": True,
                "wireguard": {
                    "private_key": key(),
                    "public_key": key(),
                    "endpoint": "198.51.100.5:51820",
                    "address": "10.64.0.2/32",
                    "address6": "fd00:64::2/128",
                    "dns": ["10.64.0.1", "fd00:64::1"],
                },
            }
        ],
        "lists": [
            {
                "id": 7,
                "name": "Video (NL)",
                "exit": 3,
                "when_down": "block",
                "resolve_via_exit": True,
                "entries": [
                    "# streaming",
                    "Example.COM  # main",
                    "",
                    "*.cdn.example.",
                    "jp",
                    "203.0.113.7",
                    "203.0.113.0/24",
                    "2001:DB8::/32",
                ],
                **list_overrides,
            }
        ],
    }


# --- config -----------------------------------------------------------------------


def test_config_defaults_and_errors():
    c = cfg()
    assert c.pipe_iface == "awg0" and c.dns_upstreams == ("9.9.9.9", "149.112.112.112") and c.dns_redirect
    c = cfg(EGRESS_DNS_UPSTREAMS="192.0.2.53, 2001:db8::53", EGRESS_BLOCK_DOT="false", EGRESS_PIPE_TOOL="wg")
    assert c.dns_upstreams == ("192.0.2.53", "2001:db8::53") and not c.block_dot and c.pipe_tool == "wg"
    for bad in (
        {"EGRESS_PIPE_IFACE": "awg0; rm"},
        {"EGRESS_DNS_UPSTREAMS": "dns.example"},
        {"EGRESS_PIPE_TOOL": "ip"},
        {"EGRESS_APPLY_INTERVAL": "soon"},
    ):
        with pytest.raises(ConfigError):
            cfg(**bad)


# --- state validation -------------------------------------------------------------


def test_validate_classifies_entries():
    s = apply.validate(state())
    lst = s["lists"][0]
    assert lst["v4"] == ["203.0.113.0/24", "203.0.113.7/32"]
    assert lst["v6"] == ["2001:db8::/32"]
    assert lst["domains"] == ["cdn.example", "example.com", "jp"]
    assert s["exits"][3]["dns4"] == ["10.64.0.1"] and s["exits"][3]["address6"] == "fd00:64::2/128"


@pytest.mark.parametrize(
    "bad",
    [
        {"entries": ["not a domain!"]},
        {"exit": 9},
        {"when_down": "maybe"},
        {"name": " padded"},
        {"id": 0},
    ],
)
def test_validate_rejects(bad):
    with pytest.raises(apply.StateError):
        apply.validate(state(**bad))


def test_validate_rejects_bad_exit():
    s = state()
    s["exits"][0]["wireguard"]["endpoint"] = "vpn.example.com:51820"
    with pytest.raises(apply.StateError):
        apply.validate(s)
    s = state()
    s["exits"][0]["wireguard"]["private_key"] = "short"
    with pytest.raises(apply.StateError):
        apply.validate(s)


# --- rendering --------------------------------------------------------------------


def test_routes_script_keeps_learned_sets():
    s = apply.validate(state())
    script = apply.render_routes(s["lists"], "awg0")
    assert "add table inet vpn_egress_routes" in script
    assert "flush set inet vpn_egress_routes l7_4" in script
    assert "add element inet vpn_egress_routes l7_4 { 203.0.113.0/24, 203.0.113.7/32 }" in script
    assert "add set inet vpn_egress_routes d7_6 { type ipv6_addr; flags timeout; timeout 2d; }" in script
    assert "flush set inet vpn_egress_routes d7_" not in script  # learned IPs survive
    assert "delete table" not in script
    assert "ip6 daddr @d7_6 ct mark set ct mark | 7 meta mark set 0x10007 return" in script


def test_rules():
    s = apply.validate(state())
    assert apply.wanted_rules(s["exits"], s["lists"]) == {
        20014: ("fwmark", "0x10007", "lookup", "1003"),
        20015: ("fwmark", "0x10007", "prohibit", ""),
        21003: ("oif", "egx3", "lookup", "1003"),
    }
    s = apply.validate(state(when_down="direct"))
    assert 20015 not in apply.wanted_rules(s["exits"], s["lists"])


def test_dnsmasq_lists_and_exit_dns():
    s = apply.validate(state())
    lists_conf, servers = apply.render_dnsmasq(s, {3: True})
    assert (
        "nftset=/cdn.example/example.com/jp/4#inet#vpn_egress_routes#d7_4,6#inet#vpn_egress_routes#d7_6" in lists_conf
    )
    assert "server=/jp/10.64.0.1@egx3" in servers
    # Exit down: with the kill switch lookups still go to the exit (and fail);
    # without it they fall back to the normal upstreams.
    assert "server=/jp/10.64.0.1@egx3" in apply.render_dnsmasq(s, {3: False})[1]
    s = apply.validate(state(when_down="direct"))
    assert "server=" not in apply.render_dnsmasq(s, {3: False})[1]


def test_firewall_and_dnsmasq_config():
    fw = firewall.render(cfg(EGRESS_PIPE_IFACE="wg9"))
    assert 'iifname "wg9" ct state new ct mark set ct mark | 0x01000000' in fw
    assert "redirect to :53" in fw and "th dport 853 reject" in fw
    fw = firewall.render(cfg(EGRESS_DNS_REDIRECT="no", EGRESS_BLOCK_DOT="no"))
    assert "redirect" not in fw and "853" not in fw
    conf = dnsmasq.render(cfg(EGRESS_DNS_UPSTREAMS="192.0.2.53"))
    assert "interface=awg0" in conf and "server=192.0.2.53" in conf
    assert "servers-file=/d/run/servers.conf" in conf and "conf-file=/d/blocklist.conf" in conf


# --- blocklists --------------------------------------------------------------------


def test_blocklist_parse_formats():
    text = """$TTL 3600
@ SOA localhost. root.localhost. 1 2 3 4 5
  NS  localhost.
; rpz comment
dns.example CNAME .
*.wild.example CNAME .
*.star.example
plain.example
0.0.0.0 hosts.example
127.0.0.1 localhost
local=/dnsmasq.example/
! adblock comment
"""
    assert blocklists.parse(text) == {
        "dns.example",
        "wild.example",
        "star.example",
        "plain.example",
        "hosts.example",
        "dnsmasq.example",
    }


def test_blocklist_config_validation():
    ok = blocklists.validate(
        {"lists": [{"name": "ads", "url": "https://lists.example/ads.txt"}], "block": ["Blocked.Example."], "allow": []}
    )
    assert ok["block"] == ["blocked.example"] and ok["lists"][0]["enabled"] is True
    ok = blocklists.validate({"block": ["# trackers", "Blocked.Example.  # old", "", "*.wild.example"]})
    assert ok["block"] == ["blocked.example", "wild.example"]
    for bad in (
        {"lists": [{"name": "Ads", "url": "https://x.example/a"}]},
        {"lists": [{"name": "ads", "url": "http://x.example/a"}]},
        {"block": ["not a domain"]},
    ):
        with pytest.raises(blocklists.ConfigError):
            blocklists.validate(bad)


def test_dnsmasq_start_is_idempotent(tmp_path, monkeypatch):
    started = []

    class FakeProc:
        def poll(self):
            return None

    monkeypatch.setattr(dnsmasq.subprocess, "Popen", lambda *a, **k: started.append(a) or FakeProc())
    d = dnsmasq.Dnsmasq(cfg(EGRESS_DATA_DIR=str(tmp_path)))
    d.prepare()
    d.start()
    d.start()
    assert len(started) == 1
    assert (tmp_path / "run").stat().st_mode & 0o777 == 0o755
