#!/usr/bin/env python3
"""
================================================================================
C2 Traffic Detection Module
================================================================================
Digital Forensics Course Project - Malicious Network Behavior Detection Framework

This module detects Command & Control (C2) beaconing patterns in network traffic.
C2 beacons are periodic communications from compromised hosts to attacker-controlled
servers, used to maintain persistence and receive commands.

Detection Methodology:
1. Group packets into flows by (src_ip, dst_ip, dst_port)
2. Calculate inter-arrival times between packets in each flow
3. Measure regularity using Coefficient of Variation (CV = std/mean)
   - Low CV indicates regular, periodic timing (suspicious)
   - High CV indicates random, human-like timing (benign)
4. Flag flows with regular timing AND sufficient packet count

References:
- Coefficient of Variation: CV = std_deviation / mean
- Beaconing threshold: CV < 0.3 indicates strong regularity
================================================================================
"""

import time
from collections import defaultdict
from typing import List, Dict, Any, Tuple

try:
    from scapy.all import rdpcap, IP, TCP, UDP
except ImportError:
    raise ImportError("scapy is required. Install: pip install scapy")

import statistics


def calculate_cv(values: List[float]) -> float:
    """
    Calculate the Coefficient of Variation (CV) for a list of values.
    
    CV = standard_deviation / mean
    A low CV (< 0.3) indicates high regularity (periodic behavior).
    A high CV (> 1.0) indicates high variability (random behavior).
    
    Args:
        values: List of inter-arrival times in seconds
        
    Returns:
        Coefficient of variation (float), or infinity if mean is zero
    """
    if not values or len(values) < 2:
        return float('inf')
    
    mean_val = statistics.mean(values)
    if mean_val == 0:
        return float('inf')
    
    # Use population std dev for small samples
    std_dev = statistics.stdev(values)
    return std_dev / mean_val


def extract_flows(packets: List[Any]) -> Dict[Tuple[str, str, int], List[float]]:
    """
    Extract network flows from a list of packets and record timestamps.
    
    A flow is defined by the tuple (source_ip, destination_ip, destination_port).
    This function groups packets by flow and collects their timestamps for
    inter-arrival time analysis.
    
    Args:
        packets: List of Scapy packet objects from a PCAP file
        
    Returns:
        Dictionary mapping flow tuples to lists of timestamps (float, epoch seconds)
    """
    flows = defaultdict(list)
    
    for pkt in packets:
        try:
            # Only process IP packets
            if not pkt.haslayer(IP):
                continue
            
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Extract destination port from TCP or UDP layer
            if pkt.haslayer(TCP):
                dst_port = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                dst_port = pkt[UDP].dport
            else:
                continue
            
            # Create flow key and append timestamp
            flow_key = (src_ip, dst_ip, dst_port)
            # Scapy timestamps are in epoch seconds (float)
            timestamp = float(pkt.time)
            flows[flow_key].append(timestamp)
            
        except Exception:
            # Skip malformed packets - common in captures with errors
            continue
    
    return dict(flows)


def calculate_inter_arrival_times(timestamps: List[float]) -> List[float]:
    """
    Calculate inter-arrival times from a sorted list of timestamps.
    
    Given timestamps t1, t2, t3, ... the inter-arrival times are:
    [t2-t1, t3-t2, ...]
    
    These are sorted to ensure chronological order before calculation.
    
    Args:
        timestamps: List of packet timestamps (float, epoch seconds)
        
    Returns:
        List of inter-arrival times in seconds
    """
    if len(timestamps) < 2:
        return []
    
    sorted_ts = sorted(timestamps)
    inter_arrivals = []
    
    for i in range(1, len(sorted_ts)):
        delta = sorted_ts[i] - sorted_ts[i - 1]
        # Filter out negative deltas (clock adjustments) and huge gaps
        if 0 <= delta < 3600:  # Max 1 hour gap to avoid session timeouts
            inter_arrivals.append(delta)
    
    return inter_arrivals


def detect_beaconing(
    pcap_file: str,
    cv_threshold: float = 0.5,
    min_packets: int = 5,
    max_cv: float = 2.0
) -> List[Dict[str, Any]]:
    """
    Detect C2 beaconing patterns in a PCAP file.
    
    Beaconing detection works by identifying flows with:
    - Regular (periodic) inter-packet timing (low Coefficient of Variation)
    - Sufficient packet count to establish a pattern
    - Reasonable intervals (not too fast, not too slow)
    
    The beaconing score is calculated as:
        score = (1 / (1 + CV)) * packet_count_weight
    Higher scores indicate more suspicious beaconing behavior.
    
    Args:
        pcap_file: Path to the PCAP file to analyze
        cv_threshold: Maximum CV to consider as beaconing (lower = more strict)
        min_packets: Minimum packets in a flow to analyze
        max_cv: Maximum CV cap for scoring purposes
        
    Returns:
        List of dictionaries containing suspicious flow details with beaconing scores
        Each dict contains: flow_key, cv, packet_count, interval_mean, beacon_score
    """
    suspicious_flows = []
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[C2 Detector] Error reading PCAP file '{pcap_file}': {e}")
        return suspicious_flows
    
    if not packets:
        print("[C2 Detector] No packets found in PCAP file.")
        return suspicious_flows
    
    # Step 1: Extract flows and their timestamps
    flows = extract_flows(packets)
    
    # Step 2: Analyze each flow for beaconing patterns
    for flow_key, timestamps in flows.items():
        # Skip flows with too few packets
        if len(timestamps) < min_packets:
            continue
        
        # Calculate inter-arrival times
        inter_arrivals = calculate_inter_arrival_times(timestamps)
        
        if not inter_arrivals:
            continue
        
        # Calculate Coefficient of Variation (regularity measure)
        cv = calculate_cv(inter_arrivals)
        
        # Skip if CV is unreasonably high (no beaconing pattern)
        if cv > max_cv or cv == float('inf'):
            continue
        
        # Calculate mean interval for reporting
        mean_interval = statistics.mean(inter_arrivals)
        
        # Calculate beaconing score:
        # Score combines regularity (1/(1+CV)) and volume (packet count)
        # Higher score = more suspicious
        regularity_score = 1.0 / (1.0 + cv)
        volume_factor = min(len(timestamps) / 20.0, 1.0)  # Cap at 20 packets
        beacon_score = (regularity_score * 0.7 + volume_factor * 0.3) * 100
        
        # Classify severity based on CV
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
        
        # Include all flows that show some regularity (up to max_cv)
        # The main filtering is done by the caller using severity/beacon_score
        suspicious_flows.append(result)
    
    # Sort by beacon score (highest first)
    suspicious_flows.sort(key=lambda x: x["beacon_score"], reverse=True)
    
    return suspicious_flows


def format_results(results: List[Dict[str, Any]]) -> str:
    """
    Format C2 detection results as a readable string for display/reporting.
    
    Args:
        results: List of detection result dictionaries
        
    Returns:
        Formatted string with all findings
    """
    output = []
    output.append("=" * 70)
    output.append("C2 BEACONING DETECTION RESULTS")
    output.append("=" * 70)
    
    if not results:
        output.append("No suspicious C2 beaconing patterns detected.")
        return "\n".join(output)
    
    output.append(f"Suspicious flows detected: {len(results)}")
    output.append("-" * 70)
    
    for i, result in enumerate(results[:20], 1):  # Show top 20
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
    # Example usage - analyze a PCAP file for C2 beaconing
    # To test: capture traffic with: sudo tcpdump -w test.pcap -i any -c 1000
    # Or use any existing PCAP file
    
    import sys
    
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    else:
        print("Usage: python c2_detector.py <pcap_file>")
        print("\nExample:")
        print("  python c2_detector.py /path/to/capture.pcap")
        print("\nThis will analyze the PCAP for C2 beaconing patterns.")
        sys.exit(1)
    
    print(f"[*] Analyzing {pcap_path} for C2 beaconing patterns...")
    results = detect_beaconing(pcap_path)
    print(format_results(results))
