#!/usr/bin/env python3
"""
================================================================================
Data Exfiltration Detection Module
================================================================================
Digital Forensics Course Project - Malicious Network Behavior Detection Framework

This module detects data exfiltration - the unauthorized transfer of data from
an organization to an external destination. Exfiltration is a critical stage in
the cyber kill chain where attackers steal sensitive information.

Exfiltration Techniques Detected:
1. Large outbound data transfers - bulk data theft
2. Unusually high outbound/inbound byte ratios - asymmetric data flow
3. Protocol abuse - using DNS, ICMP for covert channels
4. Continuous/long-duration flows - stealthy slow exfiltration

Detection Methodology:
1. Group packets into bidirectional connections (src_ip, dst_ip)
2. Count bytes in each direction (outbound vs inbound)
3. Calculate outbound/inbound ratio
4. Flag connections with large outbound volume or high ratios
5. Detect protocol anomalies (DNS with large payloads, ICMP with data)

Key Metrics:
- Total outbound bytes per connection
- Outbound/Inbound ratio (OI ratio)
- Protocol-specific payload sizes
- Connection duration
================================================================================
"""

from collections import defaultdict
from typing import List, Dict, Any, Tuple

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, DNSQR
except ImportError:
    raise ImportError("scapy is required. Install: pip install scapy")


def get_packet_size(pkt: Any) -> int:
    """
    Get the payload size of a packet.
    
    For TCP/UDP: returns the payload length (total length - header length)
    For ICMP: returns the data length
    For other: returns the full IP payload length
    
    Args:
        pkt: Scapy packet object
        
    Returns:
        Payload size in bytes
    """
    try:
        if pkt.haslayer(IP):
            # IP total length - IP header length
            ip_payload = pkt[IP].len - (pkt[IP].ihl * 4)
            return max(ip_payload, 0)
        return len(pkt.payload) if hasattr(pkt, 'payload') else 0
    except Exception:
        return 0


def extract_connections(packets: List[Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """
    Extract bidirectional connections from packets and aggregate statistics.
    
    A connection is defined by the (internal_ip, external_ip) pair.
    For each connection, tracks:
    - Outbound bytes (internal -> external)
    - Inbound bytes (external -> internal)
    - Packet counts in each direction
    - First and last timestamps
    - Protocols used
    - DNS payload sizes (for DNS exfiltration detection)
    - ICMP payload sizes (for ICMP tunnel detection)
    
    Args:
        packets: List of Scapy packet objects
        
    Returns:
        Dictionary mapping connection tuples to traffic statistics
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
    
    for pkt in packets:
        try:
            if not pkt.haslayer(IP):
                continue
            
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            pkt_size = get_packet_size(pkt)
            timestamp = float(pkt.time)
            
            # Create unordered connection key (smaller IP first for grouping)
            # We track direction by comparing src/dst
            conn_key = tuple(sorted([src_ip, dst_ip]))
            
            conn = connections[conn_key]
            conn["timestamps"].append(timestamp)
            
            # Determine direction: assume private IPs are "internal"
            # This is a heuristic - in practice, you'd know your network range
            src_private = is_private_ip(src_ip)
            dst_private = is_private_ip(dst_ip)
            
            if src_private and not dst_private:
                # Outbound: internal -> external
                conn["outbound_bytes"] += pkt_size
                conn["outbound_packets"] += 1
            elif not src_private and dst_private:
                # Inbound: external -> internal
                conn["inbound_bytes"] += pkt_size
                conn["inbound_packets"] += 1
            else:
                # Both internal or both external - assign based on first seen
                # Use a simple heuristic: if key matches (src, dst) order
                if conn_key == (src_ip, dst_ip):
                    conn["outbound_bytes"] += pkt_size
                    conn["outbound_packets"] += 1
                else:
                    conn["inbound_bytes"] += pkt_size
                    conn["inbound_packets"] += 1
            
            # Track protocols and ports
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
                    # Track DNS payload sizes for tunnel detection
                    dns_payload = pkt_size - 8  # UDP header = 8 bytes
                    conn["dns_payload_sizes"].append(dns_payload)
                    if dns_payload > 200:  # Large DNS query = suspicious
                        conn["large_dns_queries"] += 1
                conn["dst_ports"].add(pkt[UDP].dport)
            elif pkt.haslayer(ICMP):
                conn["protocols"].add("ICMP")
                icmp_payload = pkt_size - 8  # ICMP header = 8 bytes
                conn["icmp_payload_sizes"].append(icmp_payload)
                if icmp_payload > 100:  # Large ICMP payload = suspicious
                    conn["large_icmp_packets"] += 1
            
        except Exception:
            # Skip malformed packets
            continue
    
    return dict(connections)


def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is in a private/reserved range.
    
    Private IP ranges (RFC 1918):
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16
    - 127.0.0.0/8 (loopback)
    - 169.254.0.0/16 (link-local)
    
    Args:
        ip: IP address as string (e.g., "192.168.1.1")
        
    Returns:
        True if the IP is private/reserved, False otherwise
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        first_octet = int(parts[0])
        second_octet = int(parts[1])
    except ValueError:
        return False
    
    # 10.0.0.0/8
    if first_octet == 10:
        return True
    # 172.16.0.0/12
    if first_octet == 172 and 16 <= second_octet <= 31:
        return True
    # 192.168.0.0/16
    if first_octet == 192 and second_octet == 168:
        return True
    # 127.0.0.0/8 (loopback)
    if first_octet == 127:
        return True
    # 169.254.0.0/16 (link-local)
    if first_octet == 169 and second_octet == 254:
        return True
    
    return False


def detect_exfiltration(
    pcap_file: str,
    min_outbound_bytes: int = 100000,  # 100 KB
    ratio_threshold: float = 10.0,      # 10:1 outbound:inbound
    min_packets: int = 5,
    large_dns_threshold: int = 5,       # Number of large DNS queries
    large_icmp_threshold: int = 5       # Number of large ICMP packets
) -> List[Dict[str, Any]]:
    """
    Detect data exfiltration patterns in a PCAP file.
    
    Analyzes network connections for signs of unauthorized data transfer:
    1. Large outbound data volume - bulk exfiltration
    2. High outbound/inbound ratio - asymmetric data flow
    3. DNS tunneling with large payloads - covert channel
    4. ICMP tunneling with large payloads - covert channel
    
    Args:
        pcap_file: Path to the PCAP file to analyze
        min_outbound_bytes: Minimum outbound bytes to flag (default 100KB)
        ratio_threshold: Minimum O/I ratio to flag (default 10:1)
        min_packets: Minimum packets for a connection to be analyzed
        large_dns_threshold: Min large DNS queries to flag DNS tunneling
        large_icmp_threshold: Min large ICMP packets to flag ICMP tunneling
        
    Returns:
        List of dictionaries with exfiltration detection results
    """
    findings = []
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[Exfil Detector] Error reading PCAP file '{pcap_file}': {e}")
        return findings
    
    if not packets:
        print("[Exfil Detector] No packets found in PCAP file.")
        return findings
    
    # Step 1: Extract and aggregate connection statistics
    connections = extract_connections(packets)
    
    if not connections:
        print("[Exfil Detector] No IP connections found in PCAP file.")
        return findings
    
    # Step 2: Analyze each connection
    for conn_key, stats in connections.items():
        ip1, ip2 = conn_key
        
        # Skip connections with too few packets
        total_packets = stats["outbound_packets"] + stats["inbound_packets"]
        if total_packets < min_packets:
            continue
        
        outbound = stats["outbound_bytes"]
        inbound = stats["inbound_bytes"]
        
        # Calculate outbound/inbound ratio
        if inbound > 0:
            oi_ratio = outbound / inbound
        elif outbound > 0:
            # No inbound data at all - very suspicious
            oi_ratio = float('inf')
        else:
            oi_ratio = 0.0
        
        # Calculate connection duration
        if stats["timestamps"]:
            duration = max(stats["timestamps"]) - min(stats["timestamps"])
        else:
            duration = 0.0
        
        # Calculate average transfer rate (bytes/second)
        if duration > 0:
            transfer_rate = outbound / duration
        else:
            transfer_rate = 0.0
        
        flags = []
        score = 0.0
        
        # Check 1: Large outbound data volume
        if outbound >= min_outbound_bytes:
            flags.append("LARGE_OUTBOUND")
            score += min(outbound / min_outbound_bytes * 10, 40)
        
        # Check 2: High outbound/inbound ratio
        if oi_ratio >= ratio_threshold and outbound >= 10000:
            flags.append("HIGH_OI_RATIO")
            score += min(oi_ratio * 2, 30)
        
        # Check 3: DNS tunneling indicator (large DNS payloads)
        if stats["large_dns_queries"] >= large_dns_threshold:
            flags.append("DNS_TUNNELING")
            score += 25
        
        # Check 4: ICMP tunneling indicator (large ICMP payloads)
        if stats["large_icmp_packets"] >= large_icmp_threshold:
            flags.append("ICMP_TUNNELING")
            score += 25
        
        # Check 5: Long duration with steady outbound data (slow exfiltration)
        if duration > 300 and transfer_rate > 100:  # 5+ minutes, 100+ B/s
            flags.append("SLOW_EXFILTRATION")
            score += 15
        
        # Check 6: Very high transfer rate (bulk exfiltration)
        if transfer_rate > 100000:  # 100 KB/s
            flags.append("BULK_TRANSFER")
            score += 10
        
        # Only report if at least one flag triggered
        if flags:
            # Determine severity
            if score >= 60:
                severity = "HIGH"
            elif score >= 30:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # Format protocol list
            protocols = sorted(list(stats["protocols"]))
            ports = sorted(list(stats["dst_ports"]))[:5]  # Top 5 ports
            
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
    
    # Sort by exfiltration score (highest first)
    findings.sort(key=lambda x: x["exfil_score"], reverse=True)
    
    return findings


def format_results(results: List[Dict[str, Any]]) -> str:
    """
    Format data exfiltration detection results as a readable string.
    
    Args:
        results: List of detection result dictionaries
        
    Returns:
        Formatted string with all findings
    """
    output = []
    output.append("=" * 70)
    output.append("DATA EXFILTRATION DETECTION RESULTS")
    output.append("=" * 70)
    
    if not results:
        output.append("No suspicious data exfiltration patterns detected.")
        return "\n".join(output)
    
    output.append(f"Suspicious connections detected: {len(results)}")
    output.append("-" * 70)
    
    for i, result in enumerate(results[:20], 1):  # Show top 20
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
    # Example usage - analyze a PCAP file for data exfiltration
    import sys
    
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    else:
        print("Usage: python exfil_detector.py <pcap_file>")
        print("\nExample:")
        print("  python exfil_detector.py /path/to/capture.pcap")
        print("\nThis will analyze the PCAP for data exfiltration patterns.")
        sys.exit(1)
    
    print(f"[*] Analyzing {pcap_path} for data exfiltration...")
    results = detect_exfiltration(pcap_path)
    print(format_results(results))
