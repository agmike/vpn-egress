"""The router's static nftables table: pipe marks, DNS redirect, DoT block, NAT.

Replaced as a whole on start (it holds no learned state). The host firewall
must still allow forwarding from the pipe; nothing here opens ports.

Connection marks (shared with the routing table, see apply.py):
  ct mark 0x01000000     the connection came in from the pipe
  ct mark low 16 bits    the list that routes it (0 = none)
Packets of a pipe connection travelling back towards the pipe (replies,
forwarded or from local services such as dnsmasq) get meta mark 0x02000000;
an ip rule sends those to a table whose default route is the pipe. So the
networks behind the pipe, including dynamic IPv6 prefixes, need no routes.
"""

from __future__ import annotations

from .config import Config

TABLE = "inet vpn_egress"
PIPE_BIT = 0x01000000
RETURN_MARK = 0x02000000


def render(cfg: Config) -> str:
    pipe = cfg.pipe_iface
    lines = [
        f"table {TABLE}",
        f"delete table {TABLE}",
        f"table {TABLE} {{",
        "\tchain mark_pipe {",
        "\t\ttype filter hook prerouting priority mangle - 1; policy accept;",
        f'\t\tiifname "{pipe}" ct state new ct mark set ct mark | {PIPE_BIT:#010x}',
        f"\t\tct direction reply ct mark & {PIPE_BIT:#010x} == {PIPE_BIT:#010x} meta mark set {RETURN_MARK:#010x}",
        "\t}",
        "\tchain mark_pipe_local {",
        "\t\ttype route hook output priority mangle; policy accept;",
        f"\t\tct direction reply ct mark & {PIPE_BIT:#010x} == {PIPE_BIT:#010x} meta mark set {RETURN_MARK:#010x}",
        "\t}",
    ]
    if cfg.dns_redirect:
        lines += [
            "\t# All plain DNS from the pipe goes to our dnsmasq, whatever server was asked.",
            "\tchain dns_redirect {",
            "\t\ttype nat hook prerouting priority dstnat; policy accept;",
            f'\t\tiifname "{pipe}" meta l4proto {{ tcp, udp }} th dport 53 redirect to :53',
            "\t}",
        ]
    if cfg.block_dot:
        lines += [
            "\t# DNS over TLS/QUIC: clients fall back to plain DNS, which is redirected.",
            "\tchain forward {",
            "\t\ttype filter hook forward priority filter; policy accept;",
            f'\t\tiifname "{pipe}" meta l4proto {{ tcp, udp }} th dport 853 reject',
            "\t}",
        ]
    lines += [
        "\tchain postrouting {",
        "\t\ttype nat hook postrouting priority srcnat; policy accept;",
        f'\t\tiifname "{pipe}" oifname != "{pipe}" masquerade',
        "\t}",
        "}",
    ]
    return "\n".join(lines) + "\n"
