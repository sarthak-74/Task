"""
NETWORK PACKET ANALYZER
Task 1 - Network Packet Analyzer

This program captures network packets using Scapy and displays:
- Source IP address
- Destination IP address
- Protocol
- Source port
- Destination port
- Packet length
- Packet data/payload

Captured packet information is also saved to a CSV file.
"""

import argparse
import csv
import os
import sys
from datetime import datetime

from scapy.all import (
    ARP,
    ICMP,
    ICMPv6EchoRequest,
    ICMPv6EchoReply,
    IP,
    IPv6,
    Raw,
    TCP,
    UDP,
    sniff,
)


# Store captured packet information
captured_packets = []


def get_protocol(packet):
    """Identify the protocol of the packet."""

    if ARP in packet:
        return "ARP"

    if TCP in packet:
        return "TCP"

    if UDP in packet:
        return "UDP"

    if ICMP in packet:
        return "ICMP"

    if (
        ICMPv6EchoRequest in packet
        or ICMPv6EchoReply in packet
    ):
        return "ICMPv6"

    if IPv6 in packet:
        return "IPv6"

    if IP in packet:
        return "IP"

    return "OTHER"


def get_ip_addresses(packet):
    """Get source and destination IP addresses."""

    if IP in packet:
        return packet[IP].src, packet[IP].dst

    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst

    if ARP in packet:
        return packet[ARP].psrc, packet[ARP].pdst

    return "N/A", "N/A"


def get_ports(packet):
    """Get source and destination ports."""

    if TCP in packet:
        return packet[TCP].sport, packet[TCP].dport

    if UDP in packet:
        return packet[UDP].sport, packet[UDP].dport

    return "N/A", "N/A"


def get_payload(packet):
    """
    Extract packet payload.

    Printable UTF-8 payloads are displayed as text.
    Binary payloads are displayed as hexadecimal.
    """

    if Raw not in packet:
        return "N/A"

    raw_data = bytes(packet[Raw].load)

    # Try to display the payload as readable UTF-8 text.
    try:
        text_payload = raw_data.decode("utf-8")

        if all(
            char.isprintable() or char in "\r\n\t"
            for char in text_payload
        ):
            text_payload = (
                text_payload
                .replace("\r", "\\r")
                .replace("\n", "\\n")
                .replace("\t", "\\t")
            )

            if len(text_payload) > 100:
                text_payload = text_payload[:100] + "..."

            return text_payload

    except UnicodeDecodeError:
        pass

    # Binary/encrypted payload.
    # HEX preserves the actual byte values.
    hex_payload = raw_data.hex(" ")

    if len(hex_payload) > 100:
        hex_payload = hex_payload[:100] + "..."

    return f"[HEX] {hex_payload}"


def get_timestamp(packet):
    """Get the packet's capture timestamp."""

    try:
        return datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    except (
        AttributeError,
        TypeError,
        ValueError,
        OSError,
    ):
        # Fallback if packet timestamp is unavailable.
        return datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]


def process_packet(packet):
    """Process and display each captured packet."""

    timestamp = get_timestamp(packet)

    source_ip, destination_ip = get_ip_addresses(
        packet
    )

    protocol = get_protocol(packet)

    source_port, destination_port = get_ports(
        packet
    )

    packet_length = len(packet)

    payload = get_payload(packet)

    packet_info = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": destination_port,
        "packet_length": packet_length,
        "payload": payload,
    }

    captured_packets.append(packet_info)

    print(
        f"{timestamp} | "
        f"{source_ip:>20} -> "
        f"{destination_ip:<20} | "
        f"{protocol:<7} | "
        f"{str(source_port):>5} -> "
        f"{str(destination_port):<5} | "
        f"{packet_length:>5} bytes | "
        f"{payload}"
    )


def save_to_csv(filename):
    """Save captured packets to a CSV file."""

    if not captured_packets:
        print("\nNo packets were captured.")
        return

    fieldnames = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "packet_length",
        "payload",
    ]

    try:
        # Create output directory if necessary.
        output_directory = os.path.dirname(
            os.path.abspath(filename)
        )

        os.makedirs(
            output_directory,
            exist_ok=True
        )

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8",
        ) as csv_file:

            writer = csv.DictWriter(
                csv_file,
                fieldnames=fieldnames,
            )

            writer.writeheader()
            writer.writerows(captured_packets)

        print(
            f"\nPacket information saved to: {filename}"
        )

    except OSError as error:
        print(
            f"\nError saving CSV file: {error}"
        )


def show_summary():
    """Display a summary of captured packets."""

    if not captured_packets:
        return

    protocol_count = {}

    for packet in captured_packets:
        protocol = packet["protocol"]

        protocol_count[protocol] = (
            protocol_count.get(protocol, 0) + 1
        )

    print("\n" + "=" * 70)
    print("CAPTURE SUMMARY")
    print("=" * 70)

    print(
        f"Total packets captured: "
        f"{len(captured_packets)}"
    )

    print("\nPackets by protocol:")

    for protocol, count in sorted(
        protocol_count.items()
    ):
        print(
            f"  {protocol:<10}: {count}"
        )

    print("=" * 70)


def check_capture_permissions():
    """
    Check whether the current process has the privileges
    required for packet capture on macOS.
    """

    if sys.platform == "darwin":
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print()
            print("=" * 70)
            print("PACKET CAPTURE REQUIRES ADMINISTRATOR PRIVILEGES")
            print("=" * 70)
            print(
                "macOS requires elevated privileges for "
                "Scapy packet capture."
            )
            print()
            print("Run the program using:")
            print()
            print(
                "sudo /usr/local/bin/python "
                "packet_analyzer.py"
            )
            print("=" * 70)

            return False

    return True


def main():
    """Main function."""

    parser = argparse.ArgumentParser(
        description="Network Packet Analyzer using Scapy"
    )

    parser.add_argument(
        "-i",
        "--interface",
        default=None,
        help=(
            "Network interface to capture packets from "
            "(default: Scapy's default interface)"
        ),
    )

    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help=(
            "Number of packets to capture. "
            "0 means capture until CTRL+C."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        default="captured_packets.csv",
        help=(
            "CSV output filename "
            "(default: captured_packets.csv)"
        ),
    )

    args = parser.parse_args()

    # Validate count.
    if args.count < 0:
        parser.error(
            "--count must be 0 or a positive integer."
        )

    # Check packet capture privileges.
    if not check_capture_permissions():
        sys.exit(1)

    print("=" * 70)
    print("NETWORK PACKET ANALYZER")
    print("=" * 70)

    print("Capturing packets...")
    print("Press CTRL+C to stop.")

    if args.interface:
        print(f"Interface: {args.interface}")

    if args.count > 0:
        print(f"Packet limit: {args.count}")

    print("=" * 70)

    print(
        f"{'Timestamp':23} | "
        f"{'Source IP':20} -> "
        f"{'Destination IP':20} | "
        f"{'Proto':7} | "
        f"{'Sport':5} -> "
        f"{'Dport':5} | "
        f"{'Size':>5} | Payload"
    )

    print("-" * 160)

    try:
        sniff(
            iface=args.interface,
            prn=process_packet,
            count=args.count,
            store=False,
        )

    except KeyboardInterrupt:
        print(
            "\n\nPacket capture stopped by user."
        )

    except Exception as error:
        error_message = str(error)

        if (
            "Permission denied" in error_message
            or "/dev/bpf" in error_message
        ):
            print("\n" + "=" * 70)
            print("PACKET CAPTURE PERMISSION ERROR")
            print("=" * 70)
            print(
                "macOS denied access to the packet-capture "
                "interface."
            )
            print()
            print("Run the program with sudo:")
            print()
            print(
                "sudo /usr/local/bin/python "
                "packet_analyzer.py"
            )
            print("=" * 70)

        else:
            print(
                f"\nError while capturing packets: {error}"
            )

    finally:
        show_summary()
        save_to_csv(args.output)


if __name__ == "__main__":
    main()