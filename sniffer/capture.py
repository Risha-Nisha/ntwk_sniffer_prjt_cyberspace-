"""
capture.py  —  Packet capture engine wrapping Scapy's sniff().

Supports live capture on a named interface, an optional BPF filter,
a packet count limit, and a callback that receives every raw packet.
"""

from __future__ import annotations

import threading
from typing import Callable, Optional

from scapy.all import sniff, get_if_list, conf


class PacketCapture:
    """Captures packets from a network interface using Scapy."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,
        on_packet: Optional[Callable] = None,
    ) -> None:
        """
        Parameters
        ----------
        interface    : network interface name (None = Scapy default)
        bpf_filter   : BPF filter string, e.g. "tcp port 80"
        packet_count : stop after N packets  (0 = run until stopped)
        on_packet    : callback(packet) called for every captured packet
        """
        self.interface = interface or conf.iface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.on_packet = on_packet

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.captured: list = []

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @staticmethod
    def list_interfaces() -> list:
        """Return all network interfaces visible to Scapy."""
        return get_if_list()

    # ------------------------------------------------------------------
    # Capture lifecycle
    # ------------------------------------------------------------------

    def start(self, blocking: bool = False) -> None:
        """Start capturing packets.

        Parameters
        ----------
        blocking : if True, block the calling thread until capture finishes.
        """
        self._stop_event.clear()
        if blocking:
            self._run()
        else:
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Signal the capture loop to stop and wait for the thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

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
