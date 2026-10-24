"""
parser.py  —  Protocol dissectors for captured Scapy packets.

Supports: Ethernet, ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, HTTP (raw).
Returns a structured PacketInfo dataclass for every packet.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import (
    Packet,
    Ether,
    ARP,
    IP,
    IPv6,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    TCP,
    UDP,
    DNS,
    DNSQR,
    Raw,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class LayerInfo:
    name: str
    fields: dict = field(default_factory=dict)


@dataclass
class PacketInfo:
    index: int
    timestamp: str
    length: int
    layers: list = field(default_factory=list)
    summary: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    protocol: str = ""
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    info: str = ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class PacketParser:
    """Converts raw Scapy packets into structured PacketInfo objects."""

    _counter = 0

    @classmethod
    def reset_counter(cls) -> None:
        cls._counter = 0

    @classmethod
    def parse(cls, packet: Packet) -> PacketInfo:
        cls._counter += 1
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        pkt_info = PacketInfo(
            index=cls._counter,
            timestamp=ts,
            length=len(packet),
            summary=packet.summary(),
        )
        cls._parse_ethernet(packet, pkt_info)
        cls._parse_arp(packet, pkt_info)
        cls._parse_ip(packet, pkt_info)
        cls._parse_ipv6(packet, pkt_info)
        cls._parse_icmp(packet, pkt_info)
        cls._parse_tcp(packet, pkt_info)
        cls._parse_udp(packet, pkt_info)
        cls._parse_dns(packet, pkt_info)
        cls._parse_raw(packet, pkt_info)
        return pkt_info

    # ------------------------------------------------------------------
    # Layer parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ethernet(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(Ether):
            eth = packet[Ether]
            info.src_mac = eth.src
            info.dst_mac = eth.dst
            info.layers.append(LayerInfo("Ethernet", {
                "src":  eth.src,
                "dst":  eth.dst,
                "type": hex(eth.type),
            }))

    @staticmethod
    def _parse_arp(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(ARP):
            arp = packet[ARP]
            op = "Request" if arp.op == 1 else "Reply"
            info.protocol = "ARP"
            info.src_ip   = arp.psrc
            info.dst_ip   = arp.pdst
            info.info     = f"ARP {op}: {arp.psrc} -> {arp.pdst}"
            info.layers.append(LayerInfo("ARP", {
                "operation":  op,
                "sender_mac": arp.hwsrc,
                "sender_ip":  arp.psrc,
                "target_mac": arp.hwdst,
                "target_ip":  arp.pdst,
            }))

    @staticmethod
    def _parse_ip(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(IP):
            ip = packet[IP]
            info.src_ip = ip.src
            info.dst_ip = ip.dst
            if not info.protocol:
                info.protocol = "IP"
            info.layers.append(LayerInfo("IPv4", {
                "src":   ip.src,
                "dst":   ip.dst,
                "ttl":   ip.ttl,
                "proto": ip.proto,
                "id":    ip.id,
                "flags": str(ip.flags),
                "tos":   ip.tos,
            }))

    @staticmethod
    def _parse_ipv6(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(IPv6):
            ip6 = packet[IPv6]
            info.src_ip = ip6.src
            info.dst_ip = ip6.dst
            if not info.protocol:
                info.protocol = "IPv6"
            info.layers.append(LayerInfo("IPv6", {
                "src":         ip6.src,
                "dst":         ip6.dst,
                "hop_limit":   ip6.hlim,
                "next_header": ip6.nh,
            }))

    @staticmethod
    def _parse_icmp(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_types = {
                0: "Echo Reply", 8: "Echo Request",
                3: "Dest Unreachable", 11: "Time Exceeded", 5: "Redirect",
            }
            type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
            info.protocol = "ICMP"
            info.info = f"ICMP {type_name}"
            info.layers.append(LayerInfo("ICMP", {
                "type": type_name,
                "code": icmp.code,
            }))
        elif packet.haslayer(ICMPv6EchoRequest):
            info.protocol = "ICMPv6"
            info.info = "ICMPv6 Echo Request"
            info.layers.append(LayerInfo("ICMPv6", {"type": "Echo Request"}))
        elif packet.haslayer(ICMPv6EchoReply):
            info.protocol = "ICMPv6"
            info.info = "ICMPv6 Echo Reply"
            info.layers.append(LayerInfo("ICMPv6", {"type": "Echo Reply"}))

    @staticmethod
    def _parse_tcp(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = PacketParser._tcp_flags(tcp.flags)
            info.protocol = "TCP"
            info.src_port = tcp.sport
            info.dst_port = tcp.dport
            info.info = (
                f"{tcp.sport} -> {tcp.dport} [{flags}] "
                f"Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
            )
            info.layers.append(LayerInfo("TCP", {
                "src_port": tcp.sport,
                "dst_port": tcp.dport,
                "flags":    flags,
                "seq":      tcp.seq,
                "ack":      tcp.ack,
                "window":   tcp.window,
            }))

    @staticmethod
    def _tcp_flags(flags) -> str:
        flag_map = {
            "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
            "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
        }
        active = [long for short, long in flag_map.items() if short in str(flags)]
        return ",".join(active) if active else str(flags)

    @staticmethod
    def _parse_udp(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(UDP):
            udp = packet[UDP]
            if not info.protocol or info.protocol == "IP":
                info.protocol = "UDP"
            info.src_port = udp.sport
            info.dst_port = udp.dport
            if not info.info:
                info.info = f"{udp.sport} -> {udp.dport} Len={udp.len}"
            info.layers.append(LayerInfo("UDP", {
                "src_port": udp.sport,
                "dst_port": udp.dport,
                "length":   udp.len,
                "checksum": hex(udp.chksum) if udp.chksum else "-",
            }))

    @staticmethod
    def _parse_dns(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(DNS):
            dns = packet[DNS]
            info.protocol = "DNS"
            if dns.qr == 0:
                qname = dns[DNSQR].qname.decode(errors="replace") if dns.qdcount > 0 else ""
                info.info = f"DNS Query: {qname}"
                info.layers.append(LayerInfo("DNS", {
                    "type":     "Query",
                    "id":       dns.id,
                    "question": qname,
                }))
            else:
                answers = []
                ans = dns.an
                while ans and hasattr(ans, "rdata"):
                    try:
                        answers.append(str(ans.rdata))
                    except Exception:
                        pass
                    ans = ans.payload if hasattr(ans, "payload") else None
                info.info = f"DNS Response: {', '.join(answers[:3])}"
                info.layers.append(LayerInfo("DNS", {
                    "type":    "Response",
                    "id":      dns.id,
                    "answers": answers,
                }))

    @staticmethod
    def _parse_raw(packet: Packet, info: PacketInfo) -> None:
        if packet.haslayer(Raw):
            raw_data = bytes(packet[Raw])
            preview  = raw_data[:64]
            try:
                text = preview.decode("utf-8", errors="ignore")
                if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
                    first_line = text.split("\r\n")[0]
                    info.protocol = "HTTP"
                    info.info     = first_line
                    info.layers.append(LayerInfo("HTTP", {"first_line": first_line}))
                    return
            except Exception:
                pass
            info.layers.append(LayerInfo("Raw", {
                "length":  len(raw_data),
                "preview": preview.hex(),
            }))
