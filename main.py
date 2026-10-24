#!/usr/bin/env python3
"""
main.py  —  Entry point for the Network Packet Sniffer.

Usage examples
--------------
  # List available interfaces
  python main.py --list-interfaces

  # Capture on default interface (100 packets)
  python main.py -c 100

  # Capture only TCP traffic on eth0, verbose detail, save to log.json
  python main.py -i eth0 -f "tcp" -v --log capture.json

  # Capture DNS queries indefinitely (Ctrl-C to stop)
  python main.py -f "udp port 53"
"""

from __future__ import annotations

import argparse
import signal
import sys

from sniffer.capture import PacketCapture
from sniffer.parser  import PacketParser
from sniffer.display import Display


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sniffer",
        description="Network Packet Sniffer — Scapy-powered local network inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-i", "--interface", metavar="IFACE",
        help="Network interface to capture on (default: Scapy's default interface)",
    )
    parser.add_argument(
        "-f", "--filter", metavar="BPF",
        help='BPF filter expression, e.g. "tcp port 80" or "udp"',
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0, metavar="N",
        help="Stop after capturing N packets (default: 0 = unlimited)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print detailed layer breakdown for every packet",
    )
    parser.add_argument(
        "--log", metavar="FILE",
        help="Save captured packets to FILE (.txt or .json)",
    )
    parser.add_argument(
        "--list-interfaces", action="store_true",
        help="List all available network interfaces and exit",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_arg_parser()
    args   = parser.parse_args()

    # List interfaces and exit
    if args.list_interfaces:
        print("Available network interfaces:")
        for idx, iface in enumerate(PacketCapture.list_interfaces(), 1):
            print(f"  [{idx}] {iface}")
        sys.exit(0)

    # Set up display and parser
    display = Display(verbose=args.verbose, log_file=args.log)
    PacketParser.reset_counter()

    def on_packet(packet):
        pkt_info = PacketParser.parse(packet)
        display.display(pkt_info)

    # Set up capture engine
    capture = PacketCapture(
        interface=args.interface,
        bpf_filter=args.filter,
        packet_count=args.count,
        on_packet=on_packet,
    )

    # Graceful shutdown on Ctrl-C
    def handle_sigint(sig, frame):
        print("\n\n[!] Capture interrupted by user.")
        capture.stop()
        display.print_stats()
        display.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    # Print header and config
    display.print_header()
    print(f"  Interface : {args.interface or '(default)'}")
    print(f"  Filter    : {args.filter or '(none)'}")
    print(f"  Count     : {args.count if args.count else 'unlimited'}")
    if args.log:
        print(f"  Log file  : {args.log}")
    print()

    # Start capture
    try:
        capture.start(blocking=True)
    except PermissionError:
        print(
            "\n[ERROR] Permission denied.\n"
            "Packet capture requires elevated privileges.\n"
            "  * Linux/macOS : run with  sudo python main.py\n"
            "  * Windows     : run terminal as Administrator\n"
        )
        sys.exit(1)
    except OSError as exc:
        print(f"\n[ERROR] Could not open interface: {exc}")
        sys.exit(1)

    # Reached only when --count limit is hit
    display.print_stats()
    display.close()


if __name__ == "__main__":
    main()
