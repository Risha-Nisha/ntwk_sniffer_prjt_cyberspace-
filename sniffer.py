#!/usr/bin/env python3
"""
sniffer.py — Network Packet Sniffer (single-file edition)
==========================================================
A terminal-based local network packet sniffer built with Python and Scapy.

Supported protocols : Ethernet, ARP, IPv4, IPv6, ICMP/v6, TCP, UDP, DNS, HTTP

Usage examples
--------------
  # List available interfaces
  python sniffer.py --list-interfaces

  # Capture 100 packets on the default interface
  python sniffer.py -c 100

  # Capture only TCP on eth0, verbose, save to log.json
  python sniffer.py -i eth0 -f "tcp" -v --log capture.json

  # Capture DNS queries indefinitely (Ctrl-C to stop)
  python sniffer.py -f "udp port 53"

Requirements
------------
  pip install scapy colorama
  # Linux/macOS: also needs libpcap   (sudo apt install libpcap-dev)
  # Windows    : also needs Npcap     (https://npcap.com)

Elevated privileges are required for raw packet capture:
  Linux/macOS : sudo python sniffer.py
  Windows     : run terminal as Administrator
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import signal
import sys
import threading
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional, TextIO

from colorama import Fore, Style, init as colorama_init
from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    ICMP,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    IP,
    IPv6,
    Packet,
    Raw,
    TCP,
    UDP,
    Ether,
    conf,
    get_if_list,
    sniff,
)

colorama_init(autoreset=True)


# ===========================================================================
# Data model
# ===========================================================================

@dataclass
class LayerInfo:
    """Holds the name and parsed fields of one protocol layer."""
    name: str
    fields: dict = field(default_factory=dict)


@dataclass
class PacketInfo:
    """Structured representation of a single captured packet."""
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


# ===========================================================================
# Packet parser
# ===========================================================================

class PacketParser:
    """Converts raw Scapy packets into structured PacketInfo objects."""

    _counter: int = 0

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

    # -----------------------------------------------------------------------
    # Layer parsers
    # -----------------------------------------------------------------------

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


# ===========================================================================
# Packet capture engine
# ===========================================================================

class PacketCapture:
    """Captures packets from a network interface using Scapy."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,
        on_packet: Optional[Callable] = None,
    ) -> None:
        self.interface    = interface or conf.iface
        self.bpf_filter   = bpf_filter
        self.packet_count = packet_count
        self.on_packet    = on_packet

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.captured: list = []

    @staticmethod
    def list_interfaces() -> list:
        """Return all network interfaces visible to Scapy."""
        return get_if_list()

    def start(self, blocking: bool = False) -> None:
        """Start capturing. If blocking=True, block until capture ends."""
        self._stop_event.clear()
        if blocking:
            self._run()
        else:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Signal the capture loop to stop."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _run(self) -> None:
        sniff(
            iface=self.interface,
            filter=self.bpf_filter if self.bpf_filter else None,
            count=self.packet_count,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set(),
        )

    def _handle_packet(self, packet) -> None:
        self.captured.append(packet)
        if self.on_packet:
            self.on_packet(packet)


# ===========================================================================
# Terminal display
# ===========================================================================

PROTO_COLORS: dict = {
    "TCP":    Fore.CYAN,
    "UDP":    Fore.GREEN,
    "DNS":    Fore.YELLOW,
    "HTTP":   Fore.MAGENTA,
    "ICMP":   Fore.BLUE,
    "ICMPv6": Fore.BLUE,
    "ARP":    Fore.WHITE,
    "IPv6":   Fore.LIGHTCYAN_EX,
    "IP":     Fore.LIGHTWHITE_EX,
}

HEADER_COLOR  = Fore.LIGHTWHITE_EX + Style.BRIGHT
SECTION_COLOR = Fore.LIGHTYELLOW_EX + Style.BRIGHT
FIELD_COLOR   = Fore.LIGHTBLACK_EX


class Display:
    """Handles all terminal output and optional log-file writing."""

    _COL = {
        "no":    5,
        "time":  12,
        "proto": 7,
        "src":   22,
        "dst":   22,
        "len":   6,
    }

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None) -> None:
        self.verbose  = verbose
        self.log_file = log_file

        self._log_fh: Optional[TextIO]  = None
        self._log_json   = False
        self._log_records: list = []

        self._stats: dict  = defaultdict(int)
        self._total_bytes  = 0
        self._packet_count = 0

        self._terminal_width = self._get_terminal_width()
        self._open_log_file()

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def print_header(self) -> None:
        w = self._terminal_width
        print(HEADER_COLOR + "=" * w)
        print(f"{'NETWORK PACKET SNIFFER':^{w}}")
        print("=" * w + Style.RESET_ALL)
        self._print_table_row(
            no="No.", time="Time", proto="Proto",
            src="Source", dst="Destination", length="Len", info="Info",
            color=HEADER_COLOR,
        )
        print(HEADER_COLOR + "-" * w + Style.RESET_ALL)

    def display(self, pkt_info: PacketInfo) -> None:
        self._packet_count += 1
        self._total_bytes  += pkt_info.length
        self._stats[pkt_info.protocol or "OTHER"] += 1

        color = PROTO_COLORS.get(pkt_info.protocol, Fore.RESET)
        info_width = max(10, self._terminal_width
                         - sum(self._COL.values()) - 14)
        info_str = (pkt_info.info or pkt_info.summary)[:info_width]

        self._print_table_row(
            no=str(pkt_info.index),
            time=pkt_info.timestamp,
            proto=pkt_info.protocol or "?",
            src=self._format_endpoint(pkt_info.src_ip, pkt_info.src_port),
            dst=self._format_endpoint(pkt_info.dst_ip, pkt_info.dst_port),
            length=str(pkt_info.length),
            info=info_str,
            color=color,
        )

        if self.verbose:
            self.print_detail(pkt_info)

        self._write_log(pkt_info)

    def print_detail(self, pkt_info: PacketInfo) -> None:
        w = self._terminal_width
        print(SECTION_COLOR + f"  +-- Packet #{pkt_info.index} detail " + "-" * max(0, w - 24) + Style.RESET_ALL)
        for layer in pkt_info.layers:
            print(SECTION_COLOR + f"  |  [{layer.name}]" + Style.RESET_ALL)
            for k, v in layer.fields.items():
                print(f"  |    {FIELD_COLOR}{k:<18}{Style.RESET_ALL}{v}")
        print(SECTION_COLOR + "  +" + "-" * (w - 4) + Style.RESET_ALL)

    def print_stats(self) -> None:
        w = self._terminal_width
        print()
        print(HEADER_COLOR + "=" * w)
        print(f"{'SESSION STATISTICS':^{w}}")
        print("=" * w + Style.RESET_ALL)
        print(f"  {'Total packets':<30} {self._packet_count}")
        print(f"  {'Total bytes captured':<30} {self._total_bytes:,}")
        print()
        print(SECTION_COLOR + "  Protocol breakdown:" + Style.RESET_ALL)
        for proto, count in sorted(self._stats.items(), key=lambda x: -x[1]):
            bar_len = int(count / max(self._packet_count, 1) * 30)
            bar   = "#" * bar_len
            color = PROTO_COLORS.get(proto, Fore.RESET)
            print(f"  {color}{proto:<10}{Style.RESET_ALL}  {count:>5}  {color}{bar}{Style.RESET_ALL}")
        print(HEADER_COLOR + "=" * w + Style.RESET_ALL)

    def close(self) -> None:
        if self._log_fh:
            if self._log_json:
                json.dump(self._log_records, self._log_fh, indent=2)
            self._log_fh.close()
            self._log_fh = None

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _print_table_row(
        self, *, no: str, time: str, proto: str,
        src: str, dst: str, length: str, info: str, color: str = ""
    ) -> None:
        c = self._COL
        row = (
            f"{no:>{c['no']}}  "
            f"{time:<{c['time']}}  "
            f"{proto:<{c['proto']}}  "
            f"{src:<{c['src']}}  "
            f"{dst:<{c['dst']}}  "
            f"{length:>{c['len']}}  "
            f"{info}"
        )
        print(color + row + Style.RESET_ALL)

    @staticmethod
    def _format_endpoint(ip: str, port: Optional[int]) -> str:
        if ip and port:
            return f"{ip}:{port}"
        return ip or "-"

    @staticmethod
    def _get_terminal_width() -> int:
        try:
            return min(os.get_terminal_size().columns, 200)
        except OSError:
            return 120

    def _open_log_file(self) -> None:
        if not self.log_file:
            return
        self._log_json = self.log_file.endswith(".json")
        self._log_fh   = open(self.log_file, "w", encoding="utf-8")
        if not self._log_json:
            self._log_fh.write("Network Packet Sniffer — Capture Log\n")
            self._log_fh.write("=" * 80 + "\n")

    def _write_log(self, pkt_info: PacketInfo) -> None:
        if not self._log_fh:
            return
        if self._log_json:
            self._log_records.append(asdict(pkt_info))
        else:
            self._log_fh.write(
                f"[{pkt_info.index}] {pkt_info.timestamp}  "
                f"{pkt_info.protocol or '?':<7}  "
                f"{self._format_endpoint(pkt_info.src_ip, pkt_info.src_port):<25} -> "
                f"{self._format_endpoint(pkt_info.dst_ip, pkt_info.dst_port):<25}  "
                f"{pkt_info.length}B  {pkt_info.info or pkt_info.summary}\n"
            )
            self._log_fh.flush()


# ===========================================================================
# CLI
# ===========================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Network Packet Sniffer — Scapy-powered local network inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-i", "--interface", metavar="IFACE",
                        help="Network interface to capture on (default: Scapy's default)")
    parser.add_argument("-f", "--filter", metavar="BPF",
                        help='BPF filter expression, e.g. "tcp port 80"')
    parser.add_argument("-c", "--count", type=int, default=0, metavar="N",
                        help="Stop after N packets (default: 0 = unlimited)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print detailed layer breakdown for every packet")
    parser.add_argument("--log", metavar="FILE",
                        help="Save captured packets to FILE (.txt or .json)")
    parser.add_argument("--list-interfaces", action="store_true",
                        help="List all available network interfaces and exit")
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args   = parser.parse_args()

    if args.list_interfaces:
        print("Available network interfaces:")
        for idx, iface in enumerate(PacketCapture.list_interfaces(), 1):
            print(f"  [{idx}] {iface}")
        sys.exit(0)

    display = Display(verbose=args.verbose, log_file=args.log)
    PacketParser.reset_counter()

    def on_packet(packet):
        pkt_info = PacketParser.parse(packet)
        display.display(pkt_info)

    capture = PacketCapture(
        interface=args.interface,
        bpf_filter=args.filter,
        packet_count=args.count,
        on_packet=on_packet,
    )

    def handle_sigint(sig, frame):
        print("\n\n[!] Capture interrupted by user.")
        capture.stop()
        display.print_stats()
        display.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    display.print_header()
    print(f"  Interface : {args.interface or '(default)'}")
    print(f"  Filter    : {args.filter or '(none)'}")
    print(f"  Count     : {args.count if args.count else 'unlimited'}")
    if args.log:
        print(f"  Log file  : {args.log}")
    print()

    try:
        capture.start(blocking=True)
    except PermissionError:
        print(
            "\n[ERROR] Permission denied.\n"
            "Packet capture requires elevated privileges.\n"
            "  * Linux/macOS : sudo python sniffer.py\n"
            "  * Windows     : run terminal as Administrator\n"
        )
        sys.exit(1)
    except OSError as exc:
        print(f"\n[ERROR] Could not open interface: {exc}")
        sys.exit(1)

    display.print_stats()
    display.close()


if __name__ == "__main__":
    main()
