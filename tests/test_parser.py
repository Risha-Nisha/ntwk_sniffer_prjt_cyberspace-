"""
tests/test_parser.py  —  Unit tests for PacketParser (no network required).

Uses Scapy's packet construction to build synthetic packets and verifies
that PacketParser extracts the correct fields.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, ARP, Raw

from sniffer.parser import PacketParser


@pytest.fixture(autouse=True)
def reset_counter():
    PacketParser.reset_counter()


# ---------------------------------------------------------------------------
# Ethernet
# ---------------------------------------------------------------------------

class TestEthernet:
    def test_mac_addresses(self):
        pkt  = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP() / TCP()
        info = PacketParser.parse(pkt)
        assert info.src_mac == "aa:bb:cc:dd:ee:ff"
        assert info.dst_mac == "11:22:33:44:55:66"

    def test_ethernet_layer_present(self):
        pkt  = Ether() / IP() / TCP()
        info = PacketParser.parse(pkt)
        names = [l.name for l in info.layers]
        assert "Ethernet" in names


# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

class TestIPv4:
    def test_ip_addresses(self):
        pkt  = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
        info = PacketParser.parse(pkt)
        assert info.src_ip == "10.0.0.1"
        assert info.dst_ip == "10.0.0.2"

    def test_ip_layer_fields(self):
        pkt  = Ether() / IP(ttl=64, src="1.2.3.4", dst="5.6.7.8") / TCP()
        info = PacketParser.parse(pkt)
        ipv4 = next(l for l in info.layers if l.name == "IPv4")
        assert ipv4.fields["ttl"] == 64
        assert ipv4.fields["src"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# TCP
# ---------------------------------------------------------------------------

class TestTCP:
    def test_protocol_is_tcp(self):
        pkt  = Ether() / IP() / TCP(sport=12345, dport=80)
        info = PacketParser.parse(pkt)
        assert info.protocol == "TCP"

    def test_ports(self):
        pkt  = Ether() / IP() / TCP(sport=54321, dport=443)
        info = PacketParser.parse(pkt)
        assert info.src_port == 54321
        assert info.dst_port == 443

    def test_syn_flag(self):
        pkt       = Ether() / IP() / TCP(flags="S")
        info      = PacketParser.parse(pkt)
        tcp_layer = next(l for l in info.layers if l.name == "TCP")
        assert "SYN" in tcp_layer.fields["flags"]

    def test_ack_flag(self):
        pkt       = Ether() / IP() / TCP(flags="A")
        info      = PacketParser.parse(pkt)
        tcp_layer = next(l for l in info.layers if l.name == "TCP")
        assert "ACK" in tcp_layer.fields["flags"]


# ---------------------------------------------------------------------------
# UDP
# ---------------------------------------------------------------------------

class TestUDP:
    def test_protocol_is_udp(self):
        pkt  = Ether() / IP() / UDP(sport=1234, dport=5678)
        info = PacketParser.parse(pkt)
        assert info.protocol == "UDP"

    def test_ports(self):
        pkt  = Ether() / IP() / UDP(sport=9999, dport=53)
        info = PacketParser.parse(pkt)
        assert info.src_port == 9999
        assert info.dst_port == 53


# ---------------------------------------------------------------------------
# ICMP
# ---------------------------------------------------------------------------

class TestICMP:
    def test_icmp_echo_request(self):
        pkt  = Ether() / IP() / ICMP(type=8, code=0)
        info = PacketParser.parse(pkt)
        assert info.protocol == "ICMP"
        icmp_layer = next(l for l in info.layers if l.name == "ICMP")
        assert icmp_layer.fields["type"] == "Echo Request"

    def test_icmp_echo_reply(self):
        pkt  = Ether() / IP() / ICMP(type=0, code=0)
        info = PacketParser.parse(pkt)
        icmp_layer = next(l for l in info.layers if l.name == "ICMP")
        assert icmp_layer.fields["type"] == "Echo Reply"


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------

class TestARP:
    def test_arp_request(self):
        pkt  = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2")
        info = PacketParser.parse(pkt)
        assert info.protocol == "ARP"
        arp_layer = next(l for l in info.layers if l.name == "ARP")
        assert arp_layer.fields["operation"] == "Request"
        assert arp_layer.fields["sender_ip"] == "192.168.1.1"

    def test_arp_reply(self):
        pkt  = Ether() / ARP(op=2, psrc="192.168.1.2", pdst="192.168.1.1")
        info = PacketParser.parse(pkt)
        arp_layer = next(l for l in info.layers if l.name == "ARP")
        assert arp_layer.fields["operation"] == "Reply"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

class TestDNS:
    def test_dns_query(self):
        pkt = (
            Ether() / IP() / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com"))
        )
        info      = PacketParser.parse(pkt)
        assert info.protocol == "DNS"
        dns_layer = next(l for l in info.layers if l.name == "DNS")
        assert dns_layer.fields["type"] == "Query"
        assert "example.com" in dns_layer.fields["question"]


# ---------------------------------------------------------------------------
# HTTP detection via Raw layer
# ---------------------------------------------------------------------------

class TestHTTP:
    def test_http_get_detected(self):
        payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        pkt     = Ether() / IP() / TCP(dport=80) / Raw(load=payload)
        info    = PacketParser.parse(pkt)
        assert info.protocol == "HTTP"
        assert "GET" in info.info

    def test_http_response_detected(self):
        payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
        pkt     = Ether() / IP() / TCP(sport=80) / Raw(load=payload)
        info    = PacketParser.parse(pkt)
        assert info.protocol == "HTTP"


# ---------------------------------------------------------------------------
# Packet counter
# ---------------------------------------------------------------------------

class TestCounter:
    def test_counter_increments(self):
        pkt = Ether() / IP() / TCP()
        i1  = PacketParser.parse(pkt)
        i2  = PacketParser.parse(pkt)
        assert i1.index == 1
        assert i2.index == 2

    def test_counter_resets(self):
        pkt = Ether() / IP() / TCP()
        PacketParser.parse(pkt)
        PacketParser.reset_counter()
        i = PacketParser.parse(pkt)
        assert i.index == 1
