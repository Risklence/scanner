"""A Local Collector on macOS reports the network it stands on (2026-10-27).

Before, it read interfaces with Linux-only calls and reported none, so the platform could never confirm it
was on the approved network.
"""

from __future__ import annotations

from scanner_agent.network_position import parse_macos_ifconfig

# Shaped like real macOS output: Wi-Fi on a home network, plus loopback, a VPN tunnel and AirDrop.
IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:00:00:00
\tinet6 fe80::1%en0 prefixlen 64 secured scopeid 0xe
\tinet 192.168.1.46 netmask 0xffffff00 broadcast 192.168.1.255
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
awdl0: flags=8943<UP,BROADCAST,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
\tinet 169.254.10.10 netmask 0xffff0000
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.20.0.15 netmask 0xffff0000 broadcast 10.20.255.255
"""


def test_reports_the_real_networks_and_skips_loopback_tunnels_and_airdrop():
    segments = parse_macos_ifconfig(IFCONFIG)

    assert [(s.interface, s.address, s.network) for s in segments] == [
        ("en0", "192.168.1.46", "192.168.1.0/24"),
        ("en5", "10.20.0.15", "10.20.0.0/16"),
    ]


def test_output_it_cannot_read_reports_nothing_rather_than_a_guess():
    assert parse_macos_ifconfig("garbage\n\tinet nonsense netmask zz\n") == ()
