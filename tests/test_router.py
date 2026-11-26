import base64
import json
import os

import pytest

from vpn_egress.router import apply, blocklists, dnsmasq, firewall, pipe, sources
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


# --- 0.2: sources, special exits, default -----------------------------------------


def test_classify_sources():
    c = apply.classify(["JP", "NETFLIX  # svc", "as2906", "AS15169", "jp", "https://lists.example/a.txt"], "t")
    assert c["domains"] == ["jp"]
    assert {(s.kind, s.name) for s in c["sources"]} == {
        ("geoip", "JP"),
        ("geoip", "NETFLIX"),
        ("asn", "AS2906"),
        ("asn", "AS15169"),
        ("url", "https://lists.example/a.txt"),
    }
    with pytest.raises(apply.StateError):
        apply.classify(["PRIVATE"], "t")
    with pytest.raises(apply.StateError):
        apply.classify(["http://plain.example/a.txt"], "t")


def test_special_exits_and_default_rules():
    s = state()
    s["lists"].append({"id": 8, "name": "Local", "exit": "direct", "entries": ["mail.example.com"]})
    s["lists"].append({"id": 9, "name": "Drop", "exit": "block", "entries": ["192.0.2.0/24"]})
    s["default"] = {"exit": 3, "when_down": "direct"}
    v = apply.validate(s)
    rules = apply.wanted_rules(v["exits"], v["lists"], v["default"])
    assert rules[20016] == ("fwmark", "0x10008", "lookup", "main")
    assert rules[20018] == ("fwmark", "0x10009", "prohibit", "")
    assert rules[20510] == ("fwmark", "0x100ff", "lookup", "1003") and 20511 not in rules
    script = apply.render_routes(v["lists"], "awg0", v["default"])
    assert "ip daddr { 10.0.0.0/8" in script and script.rstrip().endswith("meta mark set 0x100ff")
    v["default"]["exit"] = "direct"
    assert "0x100ff" not in apply.render_routes(v["lists"], "awg0", v["default"])
    assert 20510 not in apply.wanted_rules(v["exits"], v["lists"], v["default"])


def test_dnsmasq_first_match_wins():
    s = state(entries=["example.com", "jp"])  # list 7: exit DNS via exit 3
    s["lists"].insert(0, {"id": 1, "name": "Exceptions", "exit": "direct", "entries": ["mail.example.com", "shop.jp"]})
    s["lists"].append({"id": 2, "name": "Later", "exit": "block", "entries": ["ads.example.com", "other.net"]})
    v = apply.validate(s)
    lists_conf, servers = apply.render_dnsmasq(v, {3: True})
    assert "nftset=/mail.example.com/shop.jp/" in lists_conf
    assert "nftset=/example.com/jp/" in lists_conf
    assert "ads.example.com" not in lists_conf  # covered by example.com above it
    assert "nftset=/other.net/" in lists_conf
    assert "server=/mail.example.com/#" in servers and "server=/shop.jp/#" in servers
    assert "server=/jp/10.64.0.1@egx3" in servers


def test_sources_parse_formats():
    plain = sources.parse("# c\n198.51.100.0/24\n2001:db8::/48\nexample.com\n0.0.0.0 hosts.example\n", True)
    assert plain.v4 == {"198.51.100.0/24"} and plain.v6 == {"2001:db8::/48"}
    assert plain.domains == {"example.com", "hosts.example"}
    assert not sources.parse("example.com\n198.51.100.0/24", False).domains
    js = sources.parse(
        '{"prefixes": [{"ipv4Prefix": "203.0.113.0/24"}, {"ipv6Prefix": "2001:db8:1::/48"}],'
        ' "syncToken": "123", "note": "a.b"}',
        True,
    )
    assert js.v4 == {"203.0.113.0/24"} and js.v6 == {"2001:db8:1::/48"} and not js.domains


def test_source_cache_keeps_last_good(tmp_path, monkeypatch):
    cache = sources.SourceCache(tmp_path, "https://geo.example/{name}.list", "https://asn.example/{asn}.list")
    src = sources.Source("geoip", "JP")
    monkeypatch.setattr(sources, "fetch", lambda url: "\n".join(f"10.{i}.0.0/16" for i in range(10)))
    cache.refresh({src}, max_age=0)
    assert len(cache.load(src)) == 10 and cache.meta(src)["entries"] == 10
    monkeypatch.setattr(sources, "fetch", lambda url: "10.0.0.0/16\n")  # shrank by 90%
    cache.refresh({src}, max_age=0)
    assert len(cache.load(src)) == 10 and "entries" in cache.meta(src)["error"]
    seen = []
    monkeypatch.setattr(sources, "fetch", lambda url: seen.append(url) or "10.0.0.0/8")
    cache.refresh({src}, max_age=float("inf"))  # cached: nothing to do
    assert seen == []
    cache.refresh({sources.Source("asn", "AS2906")}, max_age=float("inf"))
    assert seen == ["https://asn.example/AS2906.list"]


def test_expand_merges_sources(tmp_path, monkeypatch):
    cache = sources.SourceCache(tmp_path, "https://geo.example/{name}.list", "https://asn.example/{asn}.list")
    monkeypatch.setattr(sources, "fetch", lambda url: "198.51.100.0/25\n198.51.100.128/25\n")
    v = apply.validate(state(entries=["JP", "203.0.113.7"]))
    cache.refresh(apply.required_sources(v), max_age=0)
    info = apply.expand(v, cache)
    assert v["lists"][0]["v4"] == ["198.51.100.0/24", "203.0.113.7/32"]  # collapsed
    assert info[7][0]["name"] == "JP" and info[7][0]["entries"] == 2


def test_pipe_validate_and_render():
    c = cfg(EGRESS_PIPE_MANAGE="true", EGRESS_PIPE_PORT="443", EGRESS_PIPE_ADDRESSES="10.66.0.1/24,fd66::1/64")
    good = {
        "private_key": key(),
        "obfuscation": {"Jc": 5, "S1": 30, "H1": "100000-200000", "I1": "<b 0xc300000001><r 8><t>"},
        "peers": [
            {"id": 1, "name": "Phone", "public_key": key(), "address": "10.66.0.2/32", "address6": "fd66::2/128"},
            {
                "id": 2,
                "name": "Home",
                "kind": "site",
                "public_key": key(),
                "address": "10.66.0.3/32",
                "routes": ["0.0.0.0/0", "::/0"],
            },
        ],
    }
    v = pipe.validate(good, c)
    conf = pipe.render(v, c)
    assert "ListenPort = 443" in conf and "H1 = 100000-200000" in conf
    assert "AllowedIPs = 10.66.0.2/32, fd66::2/128" in conf
    assert "AllowedIPs = 10.66.0.3/32, 0.0.0.0/0, ::/0" in conf
    assert v["peers"][1]["networks"] == [] and v["peers"][0]["networks"] == []
    routed = pipe.validate(
        {
            **good,
            "peers": [
                {
                    "id": 3,
                    "name": "R",
                    "public_key": key(),
                    "address": "10.66.0.4/32",
                    "routes": ["192.168.10.0/24", "::/0"],
                }
            ],
        },
        c,
    )
    assert routed["peers"][0]["networks"] == ["192.168.10.0/24"]
    for bad in (
        {"obfuscation": {"Jc": "seven"}},
        {"obfuscation": {"I1": "<b 0x00>\nPostUp = rm -rf /"}},
        {"obfuscation": {"Xx": 1}},
        {"peers": [{"id": 1, "name": "P", "public_key": key(), "address": "192.0.2.5/32"}]},
        {"peers": [{"id": 1, "name": "P", "public_key": key(), "address": "10.66.0.0/24"}]},
        {"private_key": "short"},
    ):
        with pytest.raises(pipe.PipeError):
            pipe.validate({**good, **bad}, c)
    assert c.pipe_manage and c.pipe_port == 443
    with pytest.raises(ConfigError):
        cfg(EGRESS_PIPE_ENDPOINT="no port")


def test_traffic_advance_and_summary():
    from datetime import UTC, datetime

    from vpn_egress.router import traffic

    def ts(*a):
        return datetime(*a, tzinfo=UTC).timestamp()

    # First run: booted this month, so the counters so far count.
    d = traffic.advance({}, "eth0", (1000, 50), "boot-a", ts(2026, 11, 3), ts(2026, 11, 10))
    assert (d["tx"], d["rx"], d["since"]) == (1000, 50, ts(2026, 11, 3))
    d = traffic.advance(d, "eth0", (1500, 80), "boot-a", ts(2026, 11, 3), ts(2026, 11, 10, 1))
    assert (d["tx"], d["rx"]) == (1500, 80)
    # Reboot: counters start over, everything since counts.
    d = traffic.advance(d, "eth0", (200, 10), "boot-b", ts(2026, 11, 11), ts(2026, 11, 11, 1))
    assert (d["tx"], d["rx"]) == (1700, 90)
    assert d["days"]["2026-11-11"] == [200, 10]
    # Another interface: no jump.
    d = traffic.advance(d, "eth1", (10**12, 0), "boot-b", ts(2026, 11, 11), ts(2026, 11, 11, 2))
    assert d["tx"] == 1700
    # New month: the old one is kept, counting starts at the 1st.
    d = traffic.advance(d, "eth1", (10**12 + 300, 5), "boot-b", ts(2026, 11, 11), ts(2026, 12, 1, 0, 1))
    assert d["months"]["2026-11"] == [1700, 90] and (d["month"], d["tx"]) == ("2026-12", 300)
    s = traffic.summary(d, "eth1", 10**13, ts(2026, 12, 16, 12))
    assert s["since"] == ts(2026, 12, 1) and s["projected_tx"] == 600  # half the month gone
    # First run on a host that booted last month: start from zero, now.
    d = traffic.advance({}, "eth0", (5000, 5), "boot-c", ts(2026, 10, 20), ts(2026, 11, 10))
    assert d["tx"] == 0 and d["since"] == ts(2026, 11, 10)
    assert traffic.summary(d, "eth0", 0, ts(2026, 11, 10, 12))["projected_tx"] is None


def test_traffic_allowance_setting():
    assert Config.from_env({"EGRESS_TRAFFIC_ALLOWANCE": "10TB"}).traffic_allowance == 10 * 10**12
    assert Config.from_env({"EGRESS_TRAFFIC_ALLOWANCE": "1.5 GB"}).traffic_allowance == 1_500_000_000
    assert Config.from_env({}).traffic_allowance == 0
    with pytest.raises(ConfigError):
        Config.from_env({"EGRESS_TRAFFIC_ALLOWANCE": "lots"})


DNS_LOG = """\
dnsmasq[9]: started, version 2.91 cachesize 10000
dnsmasq[9]: 1 10.66.0.2/54687 query[A] www.example.com from 10.66.0.2
dnsmasq[9]: 1 10.66.0.2/54687 forwarded www.example.com to 10.64.0.1
dnsmasq[9]: 1 10.66.0.2/54687 reply www.example.com is <CNAME>
dnsmasq[9]: 1 10.66.0.2/54687 reply edge.example.net is 198.51.100.7
dnsmasq[9]: 2 10.66.0.2/37293 query[A] www.example.com from 10.66.0.2
dnsmasq[9]: 2 10.66.0.2/37293 cached www.example.com is 198.51.100.7
dnsmasq[9]: 3 10.66.0.3/58903 query[A] ads.example.org from 10.66.0.3
dnsmasq[9]: 3 10.66.0.3/58903 config ads.example.org is NXDOMAIN
dnsmasq[9]: 4 10.66.0.2/42971 query[AAAA] nothing.invalid from 10.66.0.2
dnsmasq[9]: 4 10.66.0.2/42971 forwarded nothing.invalid to 9.9.9.9
dnsmasq[9]: 4 10.66.0.2/42971 reply nothing.invalid is NXDOMAIN
"""

CT_LOG = """\
[1795714922.327640]\t    [NEW] tcp      6 120 SYN_SENT src=10.66.0.2 dst=198.51.100.7 sport=50000 dport=443 \
[UNREPLIED] src=198.51.100.7 dst=10.64.0.2 sport=443 dport=50000 mark=16777217
[1795714923.1]\t    [NEW] udp      17 30 src=10.66.0.2 dst=203.0.113.9 sport=40000 dport=443 \
[UNREPLIED] src=203.0.113.9 dst=192.0.2.10 sport=443 dport=40000 mark=16777216
[1795714924.2]\t    [NEW] udp      17 30 src=10.66.0.2 dst=9.9.9.9 sport=40001 dport=53 \
[UNREPLIED] src=10.66.0.1 dst=10.66.0.2 sport=53 dport=40001 mark=16777216
[1795714925.3]\t    [NEW] icmp     1 30 src=10.66.0.3 dst=192.168.10.5 type=8 code=0 id=3 \
[UNREPLIED] src=192.168.10.5 dst=10.66.0.3 type=0 code=0 id=3 mark=16777216
"""


def test_live_log_dns_and_connections(tmp_path):
    import ipaddress
    import time

    from vpn_egress.router.live import LiveLog, Publisher

    log = LiveLog((ipaddress.ip_interface("10.66.0.1/24"),))
    log.view = {
        "domains": {"example.com": 1, "jp": 2},
        "exit_addrs": {"10.64.0.2": 1},
        "pipe_nets": [ipaddress.ip_network("192.168.10.0/24")],
    }
    taken = [log.feed_dns(line) for line in DNS_LOG.splitlines()]
    assert taken[0] is False and all(taken[1:])  # other lines go to the router's log
    first, cached, blocked, nx = log.dns
    assert (first["name"], first["client"], first["list"], first["result"]) == (
        "www.example.com",
        "10.66.0.2",
        1,
        "answered",
    )
    assert first["server"] == "10.64.0.1" and first["answers"] == ["198.51.100.7"]
    assert cached["result"] == "cached" and blocked["result"] == "blocked" and blocked["list"] is None
    assert nx["result"] == "nxdomain" and nx["type"] == "AAAA"
    assert log.list_for("shop.co.jp") == 2 and log.list_for("example.org") is None

    for line in CT_LOG.splitlines():
        log.feed_conn(line)
    via_exit, direct, peer = log.conns  # the DNS to the server itself is left out
    assert (via_exit["name"], via_exit["list"], via_exit["via"], via_exit["port"]) == ("www.example.com", 1, 1, 443)
    assert (direct["list"], direct["via"], direct["name"]) == (None, "direct", None)
    assert peer["via"] == "pipe" and peer["proto"] == "icmp" and peer["port"] is None

    pub = Publisher(log, tmp_path, os.getuid())
    pub.tick()
    assert not (tmp_path / "live.json").exists()  # nobody is watching
    (tmp_path / "live-watch").touch()
    pub.tick()
    snap = json.loads((tmp_path / "live.json").read_text())
    assert snap["dns"][0]["name"] == "nothing.invalid" and len(snap["conns"]) == 3  # newest first
    old = time.time() - 60
    os.utime(tmp_path / "live-watch", (old, old))
    pub.tick()
    assert not (tmp_path / "live.json").exists()


def test_live_view_first_match_and_dnsmasq_query_log():
    from vpn_egress.router.dnsmasq import render

    raw = state()
    raw["lists"] = [
        {"id": 1, "name": "a", "exit": 3, "entries": ["example.com"]},
        {"id": 2, "name": "b", "exit": "direct", "entries": ["www.example.com", "example.org", "jp"]},
    ]
    view = apply.live_view(apply.validate(raw), {"peers": [{"networks": ["192.168.10.0/24"]}]})
    assert view["domains"] == {"example.com": 1, "example.org": 2, "jp": 2}
    assert view["exit_addrs"] == {"10.64.0.2": 3, "fd00:64::2": 3}
    assert [str(n) for n in view["pipe_nets"]] == ["192.168.10.0/24"]
    assert "log-queries=extra" in render(cfg(), log_queries=True) and "log-queries" not in render(cfg())


def _dns_reply(qid: int, name: str, answers: list[tuple[int, bytes]]) -> bytes:
    import struct

    from vpn_egress.router.lookup import _qname

    msg = struct.pack("!HHHHHH", qid, 0x8180, 1, len(answers), 0, 0) + _qname(name) + struct.pack("!HH", 1, 1)
    for rtype, rdata in answers:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata  # name: pointer to the question
    return msg


def test_lookup_dns_parsing_and_resolve():
    import ipaddress
    import socket
    import struct
    import threading

    from vpn_egress.router.lookup import parse_answers, resolve

    cname = b"\x04edge\x07example\x03net\x00"
    msg = _dns_reply(7, "www.example.com", [(5, cname), (1, ipaddress.IPv4Address("198.51.100.7").packed)])
    assert parse_answers(msg, 7) == ["198.51.100.7"]
    assert parse_answers(msg, 8) == []  # someone else's answer

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))

    def serve():
        for _ in range(2):
            data, addr = srv.recvfrom(512)
            qid, qtype = struct.unpack("!H", data[:2])[0], struct.unpack("!H", data[-4:-2])[0]
            rec = (1, bytes([192, 0, 2, 1])) if qtype == 1 else (28, ipaddress.IPv6Address("2001:db8::1").packed)
            srv.sendto(_dns_reply(qid, "example.com", [rec]), addr)

    threading.Thread(target=serve, daemon=True).start()
    found = resolve("example.com", "127.0.0.1", timeout=2, port=srv.getsockname()[1])
    srv.close()
    assert found == ["192.0.2.1", "2001:db8::1"]


def test_lookup_routing_reasons_and_route():
    import ipaddress

    from vpn_egress.router.lookup import routing
    from vpn_egress.router.sources import Entries

    raw = state()
    raw["lists"] = [
        {"id": 1, "name": "a", "exit": 3, "entries": ["198.51.100.0/24", "AS64500"]},
        {"id": 2, "name": "b", "exit": "direct", "entries": ["JP"]},
    ]
    st = apply.validate(raw)

    class Cache:
        def load(self, src):
            return {
                "AS64500": Entries({"198.51.100.0/25"}, set(), set()),
                "JP": Entries({"203.0.113.0/24"}, set(), set()),
            }.get(src.name)

    learned = {(2, "198.51.100.7")}

    def is_learned(list_id, ip):
        return (list_id, str(ip)) in learned

    r = routing(ipaddress.ip_address("198.51.100.7"), st, Cache(), is_learned)
    assert r["matches"] == [
        {"list": 1, "reasons": [{"kind": "range"}, {"kind": "asn", "name": "AS64500"}]},
        {"list": 2, "reasons": [{"kind": "learned"}]},
    ]
    assert r["route"] == 1  # the first match wins
    assert routing(ipaddress.ip_address("203.0.113.9"), st, Cache(), is_learned)["route"] == 2
    assert routing(ipaddress.ip_address("192.0.2.1"), st, Cache(), is_learned)["route"] == "default"
    assert routing(ipaddress.ip_address("192.168.1.1"), st, Cache(), is_learned)["route"] == "local"


def test_lookup_server_answers_over_the_socket(tmp_path, monkeypatch):
    import socket

    from vpn_egress.router import lookup

    monkeypatch.setattr(lookup, "learned", lambda list_id, ip: False)

    class Dbs:
        def get(self, name, ip):
            return (
                ({"country": {"iso_code": "CLOUDFLARE"}}, 24)
                if name == "country"
                else (
                    {"autonomous_system_number": 13335, "autonomous_system_organization": "Cloudflare, Inc."},
                    20,
                )
            )

        def info(self):
            return {"country": 1, "asn": 1}

    c = cfg(EGRESS_STATE_DIR=str(tmp_path))
    server = lookup.serve(lookup.Lookup(c, None, Dbs()), tmp_path / "lookup.sock", os.getuid())
    try:

        def ask(q):
            with socket.socket(socket.AF_UNIX) as s:
                s.connect(str(tmp_path / "lookup.sock"))
                s.sendall(json.dumps({"q": q}).encode() + b"\n")
                return json.loads(s.makefile().readline())

        r = ask("198.51.100.7")
        a = r["addresses"][0]
        assert (a["geoip"], a["route"]) == ({"code": "CLOUDFLARE", "prefix": "198.51.100.0/24"}, "default")
        assert a["asn"] == {"number": 13335, "org": "Cloudflare, Inc.", "prefix": "198.51.96.0/20"}
        assert ask("not a name!")["error"] == "not an address or a domain name"
        assert oct((tmp_path / "lookup.sock").stat().st_mode)[-3:] == "600"
    finally:
        server.shutdown()


def test_router_health(tmp_path):
    import time

    from vpn_egress.router.main import health

    c = cfg(EGRESS_STATE_DIR=str(tmp_path))
    proc = tmp_path / "proc"
    (proc / "12").mkdir(parents=True)
    (proc / "12" / "comm").write_text("python\n")
    assert health(c, proc) == "no status written yet"
    (tmp_path / "status.json").write_text("{}")
    assert health(c, proc) == "dnsmasq is not running"
    (proc / "34").mkdir()
    (proc / "34" / "comm").write_text("dnsmasq\n")
    assert health(c, proc) is None
    old = time.time() - 600
    os.utime(tmp_path / "status.json", (old, old))
    assert "apply loop is stuck" in health(c, proc)
