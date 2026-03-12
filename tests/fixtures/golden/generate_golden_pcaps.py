#!/usr/bin/env python3
"""
Generate deterministic golden PCAPs for integration testing.

These PCAPs have valid pcap headers and minimal packet data so the
upload-validate endpoint accepts them. They are NOT real traffic —
they exist to exercise the API round-trip and pipeline scaffolding.

Run standalone:  python -m tests.fixtures.golden.generate_golden_pcaps
"""

import json
import struct
from pathlib import Path

HERE = Path(__file__).parent

# PCAP global header: magic, version 2.4, timezone 0, snaplen 65535, linktype Ethernet(1)
_PCAP_GLOBAL_HDR = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

# Minimal Ethernet + IPv4 + TCP SYN packet (54 bytes)
_ETH_IP_TCP = (
    b"\x00\x01\x02\x03\x04\x05"  # dst MAC
    b"\x06\x07\x08\x09\x0a\x0b"  # src MAC
    b"\x08\x00"                    # EtherType IPv4
    # IPv4 header (20 bytes): version=4, IHL=5, total_len=40, proto=6 (TCP)
    b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06"
    b"\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
    # TCP header (20 bytes): src=12345, dst=80, seq=0, ack=0, flags=SYN
    b"\x30\x39\x00\x50\x00\x00\x00\x00\x00\x00\x00\x00"
    b"\x50\x02\xff\xff\x00\x00\x00\x00"
)

# Minimal Ethernet + IPv4 + UDP + DNS query (74 bytes)
_ETH_IP_UDP_DNS = (
    b"\x00\x01\x02\x03\x04\x05"
    b"\x06\x07\x08\x09\x0a\x0b"
    b"\x08\x00"
    # IPv4: IHL=5, total_len=60, proto=17 (UDP)
    b"\x45\x00\x00\x3c\x00\x02\x00\x00\x40\x11"
    b"\x00\x00\x0a\x00\x00\x01\x08\x08\x08\x08"
    # UDP: src=54321, dst=53, len=20
    b"\xd4\x31\x00\x35\x00\x14\x00\x00"
    # DNS query stub (12 bytes header + labels)
    b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x01\x00\x01"
)


def _pcap_packet(data: bytes, ts_sec: int = 1700000000, ts_usec: int = 0) -> bytes:
    """Build a single PCAP packet record."""
    return struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data)) + data


def _write_pcap(path: Path, packets: list[bytes]):
    """Write a complete PCAP file."""
    with open(path, "wb") as f:
        f.write(_PCAP_GLOBAL_HDR)
        for pkt in packets:
            f.write(pkt)
    return path


def generate_all():
    """Generate golden PCAP corpus in tests/fixtures/golden/."""
    HERE.mkdir(parents=True, exist_ok=True)

    # 1. small_benign.pcap — 5 TCP SYN packets (benign baseline)
    pkts = [_pcap_packet(_ETH_IP_TCP, ts_sec=1700000000 + i) for i in range(5)]
    _write_pcap(HERE / "small_benign.pcap", pkts)

    # 2. dns_queries.pcap — 3 DNS query packets
    pkts = [_pcap_packet(_ETH_IP_UDP_DNS, ts_sec=1700000000 + i) for i in range(3)]
    _write_pcap(HERE / "dns_queries.pcap", pkts)

    # 3. mixed_traffic.pcap — TCP + DNS interleaved (multi-protocol)
    pkts = []
    for i in range(4):
        pkts.append(_pcap_packet(_ETH_IP_TCP, ts_sec=1700000000 + i * 2))
        pkts.append(_pcap_packet(_ETH_IP_UDP_DNS, ts_sec=1700000000 + i * 2 + 1))
    _write_pcap(HERE / "mixed_traffic.pcap", pkts)

    # 4. empty_valid.pcap — valid header but zero packets (edge case)
    _write_pcap(HERE / "empty_valid.pcap", [])

    # 5. large_synthetic.pcap — 200 packets for pagination / performance
    pkts = [_pcap_packet(_ETH_IP_TCP, ts_sec=1700000000 + i) for i in range(200)]
    _write_pcap(HERE / "large_synthetic.pcap", pkts)

    # Write expected findings sidecars
    _write_expected_findings()

    print(f"Generated golden PCAPs in {HERE}")
    for f in sorted(HERE.glob("*.pcap")):
        print(f"  {f.name:30s} {f.stat().st_size:>8d} bytes")


def _write_expected_findings():
    """Write expected_findings.json for each golden PCAP."""
    expectations = {
        "small_benign.pcap": {
            "is_valid": True, "format": "pcap", "min_hosts": 0,
            "max_findings": 0, "description": "Benign TCP SYN baseline — zero findings expected",
        },
        "dns_queries.pcap": {
            "is_valid": True, "format": "pcap", "min_hosts": 0,
            "max_findings": 5, "description": "DNS queries — may produce low-severity findings",
        },
        "mixed_traffic.pcap": {
            "is_valid": True, "format": "pcap", "min_hosts": 0,
            "max_findings": 5, "description": "Mixed TCP+DNS — tests multi-protocol handling",
        },
        "empty_valid.pcap": {
            "is_valid": True, "format": "pcap", "min_hosts": 0,
            "max_findings": 0, "description": "Valid header, no packets — edge case",
        },
        "large_synthetic.pcap": {
            "is_valid": True, "format": "pcap", "min_hosts": 0,
            "max_findings": 10, "description": "200-packet synthetic — pagination/performance test",
        },
    }
    out = HERE / "expected_findings.json"
    out.write_text(json.dumps(expectations, indent=2) + "\n")


if __name__ == "__main__":
    generate_all()

