"""
display.py  —  Terminal display layer for the packet sniffer.

Features
--------
* Colour-coded protocol table (live, scrolling)
* Per-packet detail view (expand all layers)
* Session statistics (packet counts, bytes, protocol breakdown)
* Optional JSON / plain-text log file output
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import asdict
from typing import Optional, TextIO

from colorama import Fore, Style, init as colorama_init

from .parser import PacketInfo

colorama_init(autoreset=True)


# ---------------------------------------------------------------------------
# Colour mapping
# ---------------------------------------------------------------------------

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
VALUE_COLOR   = Style.RESET_ALL


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

class Display:
    """Handles all terminal output and optional log-file writing."""

    _COL = {
        "no":    5,
        "time":  12,
        "proto": 7,
        "src":   22,
        "dst":   22,
        "len":   6,
        "info":  0,   # fills remaining space
    }

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None) -> None:
        """
        Parameters
        ----------
        verbose  : if True, print full layer details for every packet
        log_file : path to a .txt or .json log file
        """
        self.verbose  = verbose
        self.log_file = log_file

        self._log_fh: Optional[TextIO] = None
        self._log_json = False
        self._log_records: list = []

        self._stats: dict = defaultdict(int)
        self._total_bytes  = 0
        self._packet_count = 0

        self._terminal_width = self._get_terminal_width()
        self._open_log_file()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def print_header(self) -> None:
        """Print the table header banner."""
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
        """Print a single packet line (+ verbose detail if enabled)."""
        self._packet_count += 1
        self._total_bytes  += pkt_info.length
        self._stats[pkt_info.protocol or "OTHER"] += 1

        color = PROTO_COLORS.get(pkt_info.protocol, Fore.RESET)

        info_width = max(10, self._terminal_width
                         - self._COL["no"] - self._COL["time"]
                         - self._COL["proto"] - self._COL["src"]
                         - self._COL["dst"] - self._COL["len"] - 14)
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
        """Print full layer-by-layer breakdown for one packet."""
        w = self._terminal_width
        print(SECTION_COLOR + f"  +-- Packet #{pkt_info.index} detail " + "-" * max(0, w - 24) + Style.RESET_ALL)
        for layer in pkt_info.layers:
            print(SECTION_COLOR + f"  |  [{layer.name}]" + Style.RESET_ALL)
            for k, v in layer.fields.items():
                print(f"  |    {FIELD_COLOR}{k:<18}{VALUE_COLOR}{v}")
        print(SECTION_COLOR + "  +" + "-" * (w - 4) + Style.RESET_ALL)

    def print_stats(self) -> None:
        """Print a session summary."""
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
        """Flush and close any open log file."""
        if self._log_fh:
            if self._log_json:
                json.dump(self._log_records, self._log_fh, indent=2)
            self._log_fh.close()
            self._log_fh = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
