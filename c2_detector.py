#!/usr/bin/env python3
"""
================================================================================
C2 Traffic Detection Module (Streaming Version)
================================================================================
Digital Forensics Course Project - Malicious Network Behavior Detection Framework

This module detects Command & Control (C2) beaconing patterns in network traffic.
Uses streaming packet processing (PcapReader) to handle multi-GB PCAPs without
loading everything into memory.

Detection Methodology:
1. Stream packets from PCAP using PcapReader (memory-efficient)
2. Group packets into flows by (src_ip, dst_ip, dst_port)
3. Calculate inter-arrival times between packets in each flow
4. Measure regularity using Coefficient of Variation (CV = std/mean)
   - Low CV indicates regular, periodic timing (suspicious)
   - High CV indicates random, human-like timing (benign)
5. Flag flows with regular timing AND sufficient packet count
================================================================================
"""

import time
from collections import defaultdict
from typing import List, Dict, Any, Tuple

try:
    from scapy.all import PcapReader, IP, TCP, UDP
except ImportError:
    raise ImportError("scapy is required. Install: pip install scapy")

import statistics


def calculate_cv(values: List[float]) -> float:
    """
    Calculate the Coefficient of Variation (CV) for a list of values.
    CV = standard_deviation / mean
    A low CV (< 0.3) indicates high regularity (periodic behavior).
    A high CV (> 1.0) indicates high variability (random behavior).
    """
    if not values or len(values) < 2:
        return float('inf')

    mean_val = statistics.mean(values)
    if mean_val == 0:
        return float('inf')

    std_dev = statistics.stdev(values)
    return std_dev / mean_val


def extract_flows(pcap_path: str, progress_interval: int = 50000) -> Dict[Tuple[str, str, int], List[float]]:
    """
    Extract network flows from a PCAP file using streaming (memory-efficient).

    A flow is defined by the tuple (source_ip, destination_ip, destination_port).
    Groups packets by flow and collects their timestamps for inter-arrival analysis.

    Args:
        pcap_path: Path to the PCAP file
        progress_interval: Print progress every N packets

    Returns:
        Dictionary mapping flow tuples to lists of timestamps (float, epoch seconds)
    """
    flows = defaultdict(list)
    packet_count = 0

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            packet_count += 1
            if packet_count % progress_interval == 0:
                print(f"    [C2] Processed {packet_count:,} packets...")

            try:
                if not pkt.haslayer(IP):
                    continue

                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if pkt.haslayer(TCP):
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    dst_port = pkt[UDP].dport
                else:
                    continue

                flow_key = (src_ip, dst_ip, dst_port)
                flows[flow_key].append(float(pkt.time))

            except Exception:
                continue

    print(f"    [C2] Total packets processed: {packet_count:,}")
    return dict(flows)


def calculate_inter_arrival_times(timestamps: List[float]) -> List[float]:
    """
    Calculate inter-arrival times from a sorted list of timestamps.
    Filters out negative deltas (clock adjustments) and gaps > 1 hour.
    """
    if len(timestamps) < 2:
        return []

    sorted_ts = sorted(timestamps)
    inter_arrivals = []

    for i in range(1, len(sorted_ts)):
        delta = sorted_ts[i] - sorted_ts[i - 1]
        if 0 <= delta < 3600:
            inter_arrivals.append(delta)

    return inter_arrivals


def detect_beaconing(
    pcap_file: str,
    cv_threshold: float = 0.5,
    min_packets: int = 5,
    max_cv: float = 2.0
) -> List[Dict[str, Any]]:
    """
    Detect C2 beaconing patterns in a PCAP file using streaming analysis.

    Args:
        pcap_file: Path to the PCAP file to analyze
        cv_threshold: Maximum CV to consider as beaconing
        min_packets: Minimum packets in a flow to analyze
        max_cv: Maximum CV cap for scoring purposes

    Returns:
        List of dictionaries containing suspicious flow details
    """
    suspicious_flows = []

    try:
        flows = extract_flows(pcap_file)
    except Exception as e:
        print(f"[C2 Detector] Error reading PCAP file '{pcap_file}': {e}")
        return suspicious_flows

    if not flows:
        print("[C2 Detector] No suitable flows found in PCAP file.")
        return suspicious_flows

    for flow_key, timestamps in flows.items():
        if len(timestamps) < min_packets:
            continue

        inter_arrivals = calculate_inter_arrival_times(timestamps)

        if not inter_arrivals:
            continue

        cv = calculate_cv(inter_arrivals)

        if cv > max_cv or cv == float('inf'):
            continue

        mean_interval = statistics.mean(inter_arrivals)

        regularity_score = 1.0 / (1.0 + cv)
        volume_factor = min(len(timestamps) / 20.0, 1.0)
        beacon_score = (regularity_score * 0.7 + volume_factor * 0.3) * 100

        if cv < 0.15:
            severity = "HIGH"
        elif cv < cv_threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        result = {
            "src_ip": flow_key[0],
            "dst_ip": flow_key[1],
            "dst_port": flow_key[2],
            "packet_count": len(timestamps),
            "coefficient_of_variation": round(cv, 4),
            "mean_interval_seconds": round(mean_interval, 2),
            "beacon_score": round(beacon_score, 2),
            "severity": severity,
            "inter_arrival_times": [round(x, 3) for x in inter_arrivals[:10]],
            "detection_type": "C2_BEACONING"
        }

        suspicious_flows.append(result)

    suspicious_flows.sort(key=lambda x: x["beacon_score"], reverse=True)
    return suspicious_flows


def format_results(results: List[Dict[str, Any]]) -> str:
    """Format C2 detection results as a readable string."""
    output = []
    output.append("=" * 70)
    output.append("C2 BEACONING DETECTION RESULTS")
    output.append("=" * 70)

    if not results:
        output.append("No suspicious C2 beaconing patterns detected.")
        return "\n".join(output)

    output.append(f"Suspicious flows detected: {len(results)}")
    output.append("-" * 70)

    for i, result in enumerate(results[:20], 1):
        output.append(f"\n[Finding #{i}] Severity: {result['severity']}")
        output.append(f"  Source IP:      {result['src_ip']}")
        output.append(f"  Destination:    {result['dst_ip']}:{result['dst_port']}")
        output.append(f"  Packet Count:   {result['packet_count']}")
        output.append(f"  Coeff of Var:   {result['coefficient_of_variation']}")
        output.append(f"  Mean Interval:  {result['mean_interval_seconds']}s")
        output.append(f"  Beacon Score:   {result['beacon_score']}/100")
        output.append(f"  Sample IATs:    {result['inter_arrival_times'][:5]}s")

    output.append("\n" + "=" * 70)
    return "\n".join(output)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    else:
        print("Usage: python c2_detector.py <pcap_file>")
        sys.exit(1)

    print(f"[*] Analyzing {pcap_path} for C2 beaconing patterns...")
    results = detect_beaconing(pcap_path)
    print(format_results(results))
