#!/usr/bin/env python3
"""
================================================================================
Data Exfiltration Detection Module (Streaming Version)
================================================================================
Digital Forensics Course Project - Malicious Network Behavior Detection Framework

This module detects data exfiltration using streaming packet processing.
Exfiltration Techniques Detected:
1. Large outbound data transfers
2. Unusually high outbound/inbound byte ratios
3. Protocol abuse - using DNS, ICMP for covert channels
4. Continuous/long-duration flows

Uses PcapReader for memory-efficient processing of large PCAP files.
================================================================================
"""

from collections import defaultdict
from typing import List, Dict, Any, Tuple

try:
    from scapy.all import PcapReader, IP, TCP, UDP, ICMP, DNS
except ImportError:
    raise ImportError("scapy is required. Install: pip install scapy")


def get_packet_size(pkt) -> int:
    """Get the payload size of a packet."""
    try:
        if pkt.haslayer(IP):
            ip_payload = pkt[IP].len - (pkt[IP].ihl * 4)
            return max(ip_payload, 0)
        return len(pkt.payload) if hasattr(pkt, 'payload') else 0
    except Exception:
        return 0


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False

    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False

    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 127:
        return True
    if first == 169 and second == 254:
        return True

    return False


def extract_connections_streaming(pcap_path: str, progress_interval: int = 50000) -> tuple:
    """
    Extract bidirectional connections from a PCAP file using streaming.

    Returns:
        (connections_dict, packet_count)
    """
    connections = defaultdict(lambda: {
        "outbound_bytes": 0,
        "inbound_bytes": 0,
        "outbound_packets": 0,
        "inbound_packets": 0,
        "timestamps": [],
        "protocols": set(),
        "dst_ports": set(),
        "dns_payload_sizes": [],
        "icmp_payload_sizes": [],
        "tcp_payload_sizes": [],
        "large_dns_queries": 0,
        "large_icmp_packets": 0
    })

    packet_count = 0

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            packet_count += 1
            if packet_count % progress_interval == 0:
                print(f"    [Exfil] Processed {packet_count:,} packets...")

            try:
                if not pkt.haslayer(IP):
                    continue

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                pkt_size = get_packet_size(pkt)
                timestamp = float(pkt.time)

                conn_key = tuple(sorted([src_ip, dst_ip]))
                conn = connections[conn_key]
                conn["timestamps"].append(timestamp)

                src_private = is_private_ip(src_ip)
                dst_private = is_private_ip(dst_ip)

                if src_private and not dst_private:
                    conn["outbound_bytes"] += pkt_size
                    conn["outbound_packets"] += 1
                elif not src_private and dst_private:
                    conn["inbound_bytes"] += pkt_size
                    conn["inbound_packets"] += 1
                else:
                    if conn_key == (src_ip, dst_ip):
                        conn["outbound_bytes"] += pkt_size
                        conn["outbound_packets"] += 1
                    else:
                        conn["inbound_bytes"] += pkt_size
                        conn["inbound_packets"] += 1

                if pkt.haslayer(TCP):
                    conn["protocols"].add("TCP")
                    conn["dst_ports"].add(pkt[TCP].dport)
                    tcp_payload = pkt_size - (pkt[TCP].dataofs * 4) if pkt_size > 20 else 0
                    if tcp_payload > 0:
                        conn["tcp_payload_sizes"].append(tcp_payload)
                elif pkt.haslayer(UDP):
                    conn["protocols"].add("UDP")
                    if pkt.haslayer(DNS):
                        conn["protocols"].add("DNS")
                        dns_payload = pkt_size - 8
                        conn["dns_payload_sizes"].append(dns_payload)
                        if dns_payload > 200:
                            conn["large_dns_queries"] += 1
                    conn["dst_ports"].add(pkt[UDP].dport)
                elif pkt.haslayer(ICMP):
                    conn["protocols"].add("ICMP")
                    icmp_payload = pkt_size - 8
                    conn["icmp_payload_sizes"].append(icmp_payload)
                    if icmp_payload > 100:
                        conn["large_icmp_packets"] += 1

            except Exception:
                continue

    print(f"    [Exfil] Total packets processed: {packet_count:,}")
    return dict(connections), packet_count


def detect_exfiltration(
    pcap_file: str,
    min_outbound_bytes: int = 100000,
    ratio_threshold: float = 10.0,
    min_packets: int = 5,
    large_dns_threshold: int = 5,
    large_icmp_threshold: int = 5
) -> List[Dict[str, Any]]:
    """
    Detect data exfiltration patterns in a PCAP file using streaming analysis.

    Args:
        pcap_file: Path to the PCAP file
        min_outbound_bytes: Minimum outbound bytes to flag (default 100KB)
        ratio_threshold: Minimum O/I ratio to flag (default 10:1)
        min_packets: Minimum packets for a connection to be analyzed
        large_dns_threshold: Min large DNS queries to flag
        large_icmp_threshold: Min large ICMP packets to flag

    Returns:
        List of dictionaries with exfiltration detection results
    """
    findings = []

    try:
        connections, _ = extract_connections_streaming(pcap_file)
    except Exception as e:
        print(f"[Exfil Detector] Error reading PCAP file '{pcap_file}': {e}")
        return findings

    if not connections:
        print("[Exfil Detector] No IP connections found in PCAP file.")
        return findings

    for conn_key, stats in connections.items():
        ip1, ip2 = conn_key

        total_packets = stats["outbound_packets"] + stats["inbound_packets"]
        if total_packets < min_packets:
            continue

        outbound = stats["outbound_bytes"]
        inbound = stats["inbound_bytes"]

        if inbound > 0:
            oi_ratio = outbound / inbound
        elif outbound > 0:
            oi_ratio = float('inf')
        else:
            oi_ratio = 0.0

        if stats["timestamps"]:
            duration = max(stats["timestamps"]) - min(stats["timestamps"])
        else:
            duration = 0.0

        if duration > 0:
            transfer_rate = outbound / duration
        else:
            transfer_rate = 0.0

        flags = []
        score = 0.0

        if outbound >= min_outbound_bytes:
            flags.append("LARGE_OUTBOUND")
            score += min(outbound / min_outbound_bytes * 10, 40)

        if oi_ratio >= ratio_threshold and outbound >= 10000:
            flags.append("HIGH_OI_RATIO")
            score += min(oi_ratio * 2, 30)

        if stats["large_dns_queries"] >= large_dns_threshold:
            flags.append("DNS_TUNNELING")
            score += 25

        if stats["large_icmp_packets"] >= large_icmp_threshold:
            flags.append("ICMP_TUNNELING")
            score += 25

        if duration > 300 and transfer_rate > 100:
            flags.append("SLOW_EXFILTRATION")
            score += 15

        if transfer_rate > 100000:
            flags.append("BULK_TRANSFER")
            score += 10

        if flags:
            if score >= 60:
                severity = "HIGH"
            elif score >= 30:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            protocols = sorted(list(stats["protocols"]))
            ports = sorted(list(stats["dst_ports"]))[:5]

            result = {
                "internal_ip": ip1 if is_private_ip(ip1) else ip2,
                "external_ip": ip2 if is_private_ip(ip1) else ip1,
                "outbound_bytes": outbound,
                "inbound_bytes": inbound,
                "outbound_packets": stats["outbound_packets"],
                "inbound_packets": stats["inbound_packets"],
                "oi_ratio": round(oi_ratio, 2) if oi_ratio != float('inf') else "inf",
                "duration_seconds": round(duration, 2),
                "transfer_rate_bps": round(transfer_rate, 2),
                "protocols": protocols,
                "dst_ports": ports,
                "large_dns_queries": stats["large_dns_queries"],
                "large_icmp_packets": stats["large_icmp_packets"],
                "flags": flags,
                "exfil_score": round(min(score, 100), 2),
                "severity": severity,
                "detection_type": "DATA_EXFILTRATION"
            }

            findings.append(result)

    findings.sort(key=lambda x: x["exfil_score"], reverse=True)
    return findings


def format_results(results: List[Dict[str, Any]]) -> str:
    """Format data exfiltration detection results as a readable string."""
    output = []
    output.append("=" * 70)
    output.append("DATA EXFILTRATION DETECTION RESULTS")
    output.append("=" * 70)

    if not results:
        output.append("No suspicious data exfiltration patterns detected.")
        return "\n".join(output)

    output.append(f"Suspicious connections detected: {len(results)}")
    output.append("-" * 70)

    for i, result in enumerate(results[:20], 1):
        output.append(f"\n[Finding #{i}] Severity: {result['severity']}")
        output.append(f"  Internal IP:   {result['internal_ip']}")
        output.append(f"  External IP:   {result['external_ip']}")
        output.append(f"  Outbound:      {result['outbound_bytes']:,} bytes "
                     f"({result['outbound_bytes']/1024:.1f} KB)")
        output.append(f"  Inbound:       {result['inbound_bytes']:,} bytes "
                     f"({result['inbound_bytes']/1024:.1f} KB)")
        output.append(f"  O/I Ratio:     {result['oi_ratio']}")
        output.append(f"  Duration:      {result['duration_seconds']}s")
        output.append(f"  Transfer Rate: {result['transfer_rate_bps']:.0f} bytes/s")
        output.append(f"  Protocols:     {', '.join(result['protocols'])}")
        output.append(f"  Dest Ports:    {result['dst_ports']}")
        output.append(f"  Large DNS:     {result['large_dns_queries']}")
        output.append(f"  Large ICMP:    {result['large_icmp_packets']}")
        output.append(f"  Flags:         {', '.join(result['flags'])}")
        output.append(f"  Exfil Score:   {result['exfil_score']}/100")

    output.append("\n" + "=" * 70)
    return "\n".join(output)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    else:
        print("Usage: python exfil_detector.py <pcap_file>")
        sys.exit(1)

    print(f"[*] Analyzing {pcap_path} for data exfiltration...")
    results = detect_exfiltration(pcap_path)
    print(format_results(results))
