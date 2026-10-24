# Network Packet Sniffer

A terminal-based local network packet sniffer and inspector built with Python and [Scapy](https://scapy.net/).  
Everything lives in a **single file** — `sniffer.py`.

## Features

| Feature | Details |
|---|---|
| **Live capture** | Sniffs packets on any network interface |
| **Protocol support** | Ethernet, ARP, IPv4, IPv6, ICMP/v6, TCP, UDP, DNS, HTTP |
| **BPF filters** | Standard Berkeley Packet Filter expressions |
| **Colour-coded table** | Protocol-coloured live feed in the terminal |
| **Verbose mode** | Full layer-by-layer field breakdown per packet |
| **Statistics** | Protocol breakdown at end of session |
| **Logging** | Save to `.txt` or `.json` log files |
| **Graceful shutdown** | `Ctrl-C` stops capture and prints session stats |

---

## Project Layout

```
network_sniffer/
├── sniffer.py          ← entire application (capture + parser + display + CLI)
├── requirements.txt
├── README.md
└── REPORT.md
```

---

## Requirements

- Python 3.9+
- **libpcap** (Linux / macOS) or **Npcap** (Windows) — required by Scapy

---

## Installation

```bash
# 1. Open a terminal inside the network_sniffer folder

# 2. (Recommended) create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows

# 3. Install Python dependencies
pip install -r requirements.txt
```

---

## Usage

> **Elevated privileges are required** for raw packet capture.
> - Linux / macOS : prefix with `sudo`
> - Windows       : run the terminal as **Administrator**

### List available interfaces

```bash
sudo python sniffer.py --list-interfaces
```

### Basic capture (100 packets on default interface)

```bash
sudo python sniffer.py -c 100
```

### Capture only TCP traffic on a specific interface

```bash
sudo python sniffer.py -i eth0 -f "tcp"
```

### Verbose mode — show all layer fields per packet

```bash
sudo python sniffer.py -v -c 50
```

### Capture DNS queries and save to JSON

```bash
sudo python sniffer.py -f "udp port 53" --log dns_capture.json
```

### Capture HTTP traffic and save to a text log

```bash
sudo python sniffer.py -f "tcp port 80" --log http.txt -c 200
```

---

## Command-line Reference

```
usage: sniffer [-h] [-i IFACE] [-f BPF] [-c N] [-v] [--log FILE] [--list-interfaces]

options:
  -h, --help              show this help message and exit
  -i, --interface IFACE   Network interface to capture on
  -f, --filter BPF        BPF filter expression
  -c, --count N           Stop after N packets (0 = unlimited)
  -v, --verbose           Print detailed layer breakdown for every packet
  --log FILE              Save captured packets to FILE (.txt or .json)
  --list-interfaces       List all available network interfaces and exit
```

---

## Live Terminal Output Example

```
================================================================
                    NETWORK PACKET SNIFFER
================================================================
  No.  Time          Proto    Source                  Destination            Len    Info
----------------------------------------------------------------
    1  14:32:01.123  TCP      192.168.1.5:54321       142.250.80.46:443       74    54321 -> 443 [SYN] Seq=0 Ack=0
    2  14:32:01.145  TCP      142.250.80.46:443       192.168.1.5:54321       60    443 -> 54321 [SYN,ACK]
    3  14:32:01.456  DNS      192.168.1.5:55678       8.8.8.8:53              75    DNS Query: www.example.com.
    4  14:32:01.512  DNS      8.8.8.8:53              192.168.1.5:55678       91    DNS Response: 93.184.216.34
    5  14:32:02.001  ARP      192.168.1.1             192.168.1.100           42    ARP Request: 192.168.1.1 -> 192.168.1.100
```

---

## Supported Protocols

| Layer | Protocols |
|---|---|
| Layer 2 | Ethernet, ARP |
| Layer 3 | IPv4, IPv6, ICMP, ICMPv6 |
| Layer 4 | TCP, UDP |
| Application | DNS, HTTP (plaintext detection) |

---

## Architecture (inside sniffer.py)

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
