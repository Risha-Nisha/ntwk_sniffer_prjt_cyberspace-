# Project Report — Network Packet Sniffer

## 1. Overview

This project is a **terminal-based network packet sniffer** written in Python.
It captures live network traffic from any interface on the machine, parses
multiple protocol layers, and presents the results in a colour-coded table in
the terminal. An optional log file (plain-text or JSON) can be written at the
same time.

---

## 2. Objectives

| # | Objective |
|---|---|
| 1 | Capture raw packets from a live network interface |
| 2 | Decode common protocols at every OSI layer |
| 3 | Display packets in a readable, colour-coded terminal table |
| 4 | Allow the user to filter traffic with BPF expressions |
| 5 | Support saving captured data to `.txt` or `.json` log files |
| 6 | Print session statistics on exit |
| 7 | Deliver the entire tool as a single, self-contained Python file |

---

## 3. Technologies Used

| Technology | Role |
|---|---|
| **Python 3.9+** | Primary language |
| **Scapy** (`scapy>=2.5.0`) | Raw packet capture and protocol dissection |
| **colorama** (`colorama>=0.4.6`) | Cross-platform ANSI colour output |
| **libpcap / Npcap** | OS-level packet capture driver (Linux/macOS / Windows) |

---

## 4. Architecture

The application is structured as three cooperating classes inside a single
file (`sniffer.py`):

```
              +-----------------+
Network ----> | PacketCapture   |   wraps scapy.sniff()
              +--------+--------+
                       | raw Scapy packet
                       v
              +-----------------+
              | PacketParser    |   protocol dissectors → PacketInfo
              +--------+--------+
                       | PacketInfo dataclass
                       v
              +-----------------+
              |    Display      |   terminal UI + log file writer
              +-----------------+
```

### 4.1 PacketCapture

- Wraps Scapy's `sniff()` function.
- Supports a named interface, a BPF filter, a packet-count limit, and a
  callback that is invoked for every captured packet.
- Can run in blocking mode (CLI usage) or in a background daemon thread
  (programmatic usage).
- Exposes a `stop()` method for clean shutdown on `Ctrl-C`.

### 4.2 PacketParser

- Receives a raw Scapy `Packet` object and returns a `PacketInfo` dataclass.
- Separate `_parse_*` methods handle each protocol layer independently, so
  new protocols can be added without touching the others.
- Keeps a global packet counter so every `PacketInfo` has a unique index.

**Supported protocols:**

| Layer | Protocols |
|---|---|
| Layer 2 | Ethernet, ARP |
| Layer 3 | IPv4, IPv6, ICMP, ICMPv6 |
| Layer 4 | TCP, UDP |
| Application | DNS, HTTP (plaintext first-line detection) |

### 4.3 Display

- Prints a live, colour-coded packet table to the terminal.
- Adapts column widths to the current terminal width.
- In `--verbose` mode, expands every layer's fields below its row.
- Writes a `.txt` or `.json` log file in parallel when `--log` is supplied.
- `print_stats()` summarises total packets, total bytes, and per-protocol
  counts with a simple bar chart.

---

## 5. Data Model

```python
@dataclass
class PacketInfo:
    index:     int           # sequential packet number
    timestamp: str           # HH:MM:SS.mmm
    length:    int           # bytes
    layers:    list          # list[LayerInfo]
    summary:   str           # Scapy one-line summary (fallback)
    src_ip:    str
    dst_ip:    str
    src_mac:   str
    dst_mac:   str
    protocol:  str           # top-level protocol label
    src_port:  Optional[int]
    dst_port:  Optional[int]
    info:      str           # human-readable description
```

---

## 6. Usage

### Installation

```bash
pip install -r requirements.txt
```

### Running

> Raw packet capture requires **elevated privileges**  
> (Linux/macOS: `sudo` · Windows: Administrator terminal).

```bash
# List interfaces
sudo python sniffer.py --list-interfaces

# Capture 100 packets
sudo python sniffer.py -c 100

# Capture TCP on eth0 with verbose output, save to JSON
sudo python sniffer.py -i eth0 -f "tcp" -v --log capture.json

# Capture DNS queries indefinitely (Ctrl-C to stop)
sudo python sniffer.py -f "udp port 53"
```

### Command-line Options

| Flag | Description |
|---|---|
| `-i / --interface` | Network interface to capture on |
| `-f / --filter` | BPF filter expression |
| `-c / --count` | Stop after N packets (0 = unlimited) |
| `-v / --verbose` | Print layer details for every packet |
| `--log FILE` | Save to `.txt` or `.json` log file |
| `--list-interfaces` | Print available interfaces and exit |

---

## 7. Sample Output

```
================================================================
                    NETWORK PACKET SNIFFER
================================================================
  No.  Time          Proto    Source                  Destination            Len    Info
----------------------------------------------------------------
    1  14:32:01.123  TCP      192.168.1.5:54321       142.250.80.46:443       74    54321 -> 443 [SYN]
    2  14:32:01.456  DNS      192.168.1.5:55678       8.8.8.8:53              75    DNS Query: www.example.com.
    3  14:32:01.512  DNS      8.8.8.8:53              192.168.1.5:55678       91    DNS Response: 93.184.216.34
    4  14:32:02.001  ARP      192.168.1.1             192.168.1.100           42    ARP Request: 192.168.1.1 -> 192.168.1.100

================================================================
                     SESSION STATISTICS
================================================================
  Total packets                  4
  Total bytes captured           282

  Protocol breakdown:
  TCP            2  ##############
  DNS            1  #######
  ARP            1  #######
================================================================
```

---

## 8. Limitations

- **HTTP detection** is limited to plaintext traffic on port 80; HTTPS (TLS)
  payloads are not decrypted.
- **Requires root / Administrator** — this is an OS-level restriction for raw
  sockets and cannot be worked around without a separate capture daemon.
- Tested on Python 3.9–3.12 with Scapy 2.5.x and 2.6.x.

---

## 9. File Structure

```
network_sniffer/
├── sniffer.py          ← complete application (single file)
├── requirements.txt    ← Python dependencies
├── README.md           ← installation & usage guide
└── REPORT.md           ← this document
```

---

## 10. Conclusion

The Network Packet Sniffer meets all stated objectives: it captures live
traffic, decodes nine protocols across four OSI layers, presents results in a
readable colour-coded terminal UI, supports BPF filtering and log-file output,
and is delivered as a single portable Python file requiring only two third-party
packages (`scapy` and `colorama`).
