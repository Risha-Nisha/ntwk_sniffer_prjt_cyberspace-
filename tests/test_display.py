"""
tests/test_display.py  —  Unit tests for the Display layer.

Tests formatting helpers and stats accumulation without a real terminal.
"""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sniffer.display import Display
from sniffer.parser  import PacketInfo, LayerInfo


def _make_pkt(idx=1, proto="TCP", src_ip="1.2.3.4", dst_ip="5.6.7.8",
              src_port=1234, dst_port=80, info="test"):
    return PacketInfo(
        index=idx,
        timestamp="12:00:00.000",
        length=64,
        layers=[LayerInfo("TCP", {"src_port": src_port, "dst_port": dst_port})],
        protocol=proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        info=info,
        summary="",
    )


class TestDisplayFormatEndpoint:
    def test_with_port(self):
        assert Display._format_endpoint("192.168.1.1", 443) == "192.168.1.1:443"

    def test_without_port(self):
        assert Display._format_endpoint("192.168.1.1", None) == "192.168.1.1"

    def test_empty_ip(self):
        assert Display._format_endpoint("", None) == "-"


class TestDisplayStats:
    def test_stats_accumulate(self):
        d = Display()
        d.display(_make_pkt(idx=1, proto="TCP"))
        d.display(_make_pkt(idx=2, proto="UDP"))
        d.display(_make_pkt(idx=3, proto="TCP"))
        assert d._stats["TCP"] == 2
        assert d._stats["UDP"] == 1
        assert d._packet_count == 3
        assert d._total_bytes == 192   # 3 x 64

    def test_bytes_accumulated(self):
        d = Display()
        d.display(_make_pkt(idx=1))
        assert d._total_bytes == 64


class TestDisplayLogFile:
    def test_text_log_written(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            path = f.name
        try:
            d = Display(log_file=path)
            d.display(_make_pkt(idx=1, proto="TCP", info="hello"))
            d.close()
            content = open(path).read()
            assert "TCP" in content
            assert "hello" in content
        finally:
            os.unlink(path)

    def test_json_log_written(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            path = f.name
        try:
            d = Display(log_file=path)
            d.display(_make_pkt(idx=1, proto="DNS", info="example.com"))
            d.close()
            records = json.loads(open(path).read())
            assert isinstance(records, list)
            assert records[0]["protocol"] == "DNS"
        finally:
            os.unlink(path)
