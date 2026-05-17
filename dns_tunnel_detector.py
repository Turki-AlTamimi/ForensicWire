#!/usr/bin/env python3
"""
================================================================================
DNS Tunneling Detection Module (Streaming Version)
================================================================================
Digital Forensics Course Project - Malicious Network Behavior Detection Framework

This module detects DNS tunneling using streaming packet processing.
DNS Tunneling Indicators:
1. High entropy (randomness) in query names
2. Unusually long domain names
3. High volume of queries to specific domains
4. TXT records with large payloads

Uses PcapReader for memory-efficient processing of large PCAP files.
================================================================================
"""

import math
import re
from collections import Counter, defaultdict
from typing import List, Dict, Any

try:
    from scapy.all import PcapReader, IP, UDP, TCP, DNS, DNSQR
except ImportError:
    raise ImportError("scapy is required. Install: pip install scapy")


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0

    char_counts = Counter(data)
    total_chars = len(data)
    entropy = 0.0

    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)

    return entropy


def extract_domain_from_query(query_name: str) -> str:
    """Extract the base domain from a full DNS query name."""
    parts = query_name.strip('.').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return query_name


def analyze_dns_query(query_name: str) -> Dict[str, Any]:
    """Analyze a single DNS query for tunneling indicators."""
    clean_name = query_name.strip('.')

    if not clean_name:
        return {}

    entropy = calculate_entropy(clean_name)
    query_length = len(clean_name)
    subdomain_parts = clean_name.split('.')
    subdomain_count = len(subdomain_parts) - 1
    longest_subdomain = max(len(part) for part in subdomain_parts) if subdomain_parts else 0
    base64_like = bool(re.search(r'[A-Z0-9+/]', clean_name))

    if len(subdomain_parts) > 2:
        subdomain_text = ''.join(subdomain_parts[:-2])
        subdomain_entropy = calculate_entropy(subdomain_text) if subdomain_text else 0.0
    else:
        subdomain_entropy = 0.0

    return {
        "query_name": clean_name,
        "entropy": round(entropy, 4),
        "query_length": query_length,
        "subdomain_count": subdomain_count,
        "longest_subdomain": longest_subdomain,
        "subdomain_entropy": round(subdomain_entropy, 4),
        "base64_like": base64_like
    }


def get_query_type_name(qtype: int) -> str:
    """Convert DNS query type number to human-readable name."""
    type_names = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
        48: "DNSKEY", 43: "DS", 46: "RRSIG", 47: "NSEC"
    }
    return type_names.get(qtype, f"TYPE{qtype}")


def extract_dns_queries_streaming(pcap_path: str, progress_interval: int = 50000) -> tuple:
    """
    Extract DNS queries from a PCAP file using streaming.

    Returns:
        (queries_list, domain_counts_dict, packet_count)
    """
    queries = []
    domain_counts = Counter()
    packet_count = 0

    with PcapReader(pcap_path) as pcap:
        for pkt in pcap:
            packet_count += 1
            if packet_count % progress_interval == 0:
                print(f"    [DNS] Processed {packet_count:,} packets...")

            try:
                if not pkt.haslayer(IP):
                    continue

                is_dns = False
                if pkt.haslayer(UDP) and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
                    is_dns = True
                elif pkt.haslayer(TCP) and (pkt[TCP].dport == 53 or pkt[TCP].sport == 53):
                    is_dns = True

                if not is_dns:
                    continue

                if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
                    continue

                dns = pkt[DNS]
                dnsqr = pkt[DNSQR]

                if dns.qr != 0:
                    continue

                query_name = dnsqr.qname
                if isinstance(query_name, bytes):
                    query_name = query_name.decode('utf-8', errors='ignore')

                if not query_name or query_name == '.':
                    continue

                qtype = dnsqr.qtype
                qtype_name = get_query_type_name(qtype)
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                clean_name = query_name.strip('.')
                queries.append({
                    "query_name": clean_name,
                    "query_type": qtype,
                    "query_type_name": qtype_name,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "timestamp": float(pkt.time)
                })

                domain = extract_domain_from_query(clean_name)
                domain_counts[domain] += 1

            except Exception:
                continue

    print(f"    [DNS] Total packets processed: {packet_count:,}")
    return queries, dict(domain_counts), packet_count


def detect_dns_tunneling(
    pcap_file: str,
    entropy_threshold: float = 3.5,
    length_threshold: int = 50,
    query_count_threshold: int = 20,
    subdomain_entropy_threshold: float = 3.0
) -> List[Dict[str, Any]]:
    """
    Detect DNS tunneling in a PCAP file using streaming analysis.

    Args:
        pcap_file: Path to the PCAP file
        entropy_threshold: Minimum entropy to flag (default 3.5)
        length_threshold: Minimum query length to flag (default 50)
        query_count_threshold: Min queries to a domain to flag (default 20)
        subdomain_entropy_threshold: Min subdomain entropy to flag (default 3.0)

    Returns:
        List of dictionaries with tunneling detection results
    """
    findings = []

    try:
        dns_queries, domain_counts, _ = extract_dns_queries_streaming(pcap_file)
    except Exception as e:
        print(f"[DNS Detector] Error reading PCAP file '{pcap_file}': {e}")
        return findings

    if not dns_queries:
        print("[DNS Detector] No DNS queries found in PCAP file.")
        return findings

    # Analyze each unique query
    analyzed_queries = {}

    for query in dns_queries:
        query_name = query["query_name"]

        if query_name in analyzed_queries:
            continue

        analysis = analyze_dns_query(query_name)
        if not analysis:
            continue

        analysis["src_ip"] = query["src_ip"]
        analysis["dst_ip"] = query["dst_ip"]
        analysis["query_type_name"] = query["query_type_name"]
        analysis["domain"] = extract_domain_from_query(query_name)
        analysis["domain_query_count"] = domain_counts.get(analysis["domain"], 1)

        analyzed_queries[query_name] = analysis

    # Flag suspicious queries
    flagged_queries = set()

    for query_name, analysis in analyzed_queries.items():
        flags = []
        score = 0.0

        if analysis["entropy"] >= entropy_threshold:
            flags.append("HIGH_ENTROPY")
            score += (analysis["entropy"] - 3.0) * 20

        if analysis["query_length"] >= length_threshold:
            flags.append("LONG_QUERY")
            score += (analysis["query_length"] - 40) * 0.5

        if analysis["subdomain_entropy"] >= subdomain_entropy_threshold:
            flags.append("HIGH_SUBDOMAIN_ENTROPY")
            score += (analysis["subdomain_entropy"] - 2.5) * 15

        if analysis["base64_like"] and analysis["entropy"] > 3.0:
            flags.append("BASE64_LIKE")
            score += 10

        if analysis["domain_query_count"] >= query_count_threshold:
            flags.append("HIGH_VOLUME_DOMAIN")
            score += min(analysis["domain_query_count"] / 5, 20)

        if analysis["query_type_name"] == "TXT":
            flags.append("TXT_QUERY")
            score += 15

        if analysis["subdomain_count"] >= 4:
            flags.append("MANY_SUBDOMAINS")
            score += analysis["subdomain_count"] * 3

        if flags:
            if score >= 60:
                severity = "HIGH"
            elif score >= 30:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            result = {
                "query_name": query_name,
                "domain": analysis["domain"],
                "src_ip": analysis["src_ip"],
                "dst_ip": analysis["dst_ip"],
                "entropy": analysis["entropy"],
                "query_length": analysis["query_length"],
                "subdomain_count": analysis["subdomain_count"],
                "subdomain_entropy": analysis["subdomain_entropy"],
                "query_type": analysis["query_type_name"],
                "domain_query_count": analysis["domain_query_count"],
                "flags": flags,
                "tunnel_score": round(min(score, 100), 2),
                "severity": severity,
                "detection_type": "DNS_TUNNELING"
            }

            if query_name not in flagged_queries:
                findings.append(result)
                flagged_queries.add(query_name)

    findings.sort(key=lambda x: x["tunnel_score"], reverse=True)
    return findings


def format_results(results: List[Dict[str, Any]]) -> str:
    """Format DNS tunneling detection results as a readable string."""
    output = []
    output.append("=" * 70)
    output.append("DNS TUNNELING DETECTION RESULTS")
    output.append("=" * 70)

    if not results:
        output.append("No suspicious DNS tunneling patterns detected.")
        return "\n".join(output)

    output.append(f"Suspicious DNS queries detected: {len(results)}")
    output.append("-" * 70)

    for i, result in enumerate(results[:20], 1):
        output.append(f"\n[Finding #{i}] Severity: {result['severity']}")
        output.append(f"  Query Name:    {result['query_name']}")
        output.append(f"  Domain:        {result['domain']}")
        output.append(f"  Source IP:     {result['src_ip']}")
        output.append(f"  DNS Server:    {result['dst_ip']}")
        output.append(f"  Entropy:       {result['entropy']}")
        output.append(f"  Query Length:  {result['query_length']} chars")
        output.append(f"  Subdomains:    {result['subdomain_count']}")
        output.append(f"  Subdom Entropy: {result['subdomain_entropy']}")
        output.append(f"  Query Type:    {result['query_type']}")
        output.append(f"  Domain Count:  {result['domain_query_count']} queries")
        output.append(f"  Flags:         {', '.join(result['flags'])}")
        output.append(f"  Tunnel Score:  {result['tunnel_score']}/100")

    output.append("\n" + "=" * 70)
    return "\n".join(output)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    else:
        print("Usage: python dns_tunnel_detector.py <pcap_file>")
        sys.exit(1)

    print(f"[*] Analyzing {pcap_path} for DNS tunneling...")
    results = detect_dns_tunneling(pcap_path)
    print(format_results(results))
