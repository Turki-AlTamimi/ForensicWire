#!/usr/bin/env python3
"""
================================================================================
DNS Tunneling Detection Module
================================================================================
Digital Forensics Course Project - Malicious Network Behavior Detection Framework

This module detects DNS tunneling, a technique where attackers encode data
into DNS queries and responses to bypass firewalls and exfiltrate data.

DNS Tunneling Indicators:
1. High entropy (randomness) in query names - encoded data looks random
2. Unusually long domain names - normal queries are short
3. High volume of queries to specific domains - exfiltration generates traffic
4. TXT records with large payloads - commonly abused for data transfer

Detection Methodology:
1. Extract DNS queries from PCAP (UDP port 53 or TCP port 53)
2. Calculate Shannon entropy of each query name
3. Measure query name length
4. Count query frequency per domain
5. Flag queries exceeding thresholds

Shannon Entropy Formula:
    H(X) = -sum(P(x) * log2(P(x)))
    Where P(x) is the frequency of character x in the string
    Higher entropy = more random = more suspicious
    
    Example entropy ranges:
    - "google.com"           -> ~2.8 (low, readable)
    - "aHR0cHM6Ly9leGFtcGxl" -> ~3.9 (high, base64 encoded)
    - Normal domain          -> 2.0 - 3.5 typical
    - Encoded/tunneled data  -> 3.5+ suspicious
================================================================================
"""

import math
import re
from collections import Counter, defaultdict
from typing import List, Dict, Any, Tuple

try:
    from scapy.all import rdpcap, IP, UDP, TCP, DNS, DNSQR
except ImportError:
    raise ImportError("scapy is required. Install: pip install scapy")


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Shannon Entropy: H(X) = -sum(P(x) * log2(P(x)))
    Where P(x) is the frequency of character x in the string.
    
    Higher entropy indicates more randomness, which is characteristic
    of encoded or encrypted data used in DNS tunneling.
    
    Args:
        data: String to calculate entropy for (e.g., DNS query name)
        
    Returns:
        Shannon entropy value (float, typically 0.0 to ~5.0 for domain names)
    """
    if not data:
        return 0.0
    
    # Count frequency of each character
    char_counts = Counter(data)
    total_chars = len(data)
    
    # Calculate entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * math.log2(probability)
    
    return entropy


def extract_domain_from_query(query_name: str) -> str:
    """
    Extract the base domain from a full DNS query name.
    
    For example:
    - "data.example.com" -> "example.com"
    - "a.b.c.malicious.com" -> "malicious.com"
    
    Args:
        query_name: Full DNS query name (e.g., "subdomain.example.com")
        
    Returns:
        Base domain (last two or three parts)
    """
    parts = query_name.strip('.').split('.')
    if len(parts) >= 2:
        # Return last two parts (e.g., "example.com")
        return '.'.join(parts[-2:])
    return query_name


def analyze_dns_query(query_name: str) -> Dict[str, Any]:
    """
    Analyze a single DNS query for tunneling indicators.
    
    Checks:
    1. Query name length (long names = suspicious)
    2. Shannon entropy (high entropy = encoded data)
    3. Subdomain count (many subdomains = data encoding)
    4. Character distribution (high ratio of alphanumeric = encoded)
    
    Args:
        query_name: The DNS query name to analyze
        
    Returns:
        Dictionary with analysis results
    """
    # Remove trailing dot if present
    clean_name = query_name.strip('.')
    
    if not clean_name:
        return {}
    
    # Calculate entropy of the full query name
    entropy = calculate_entropy(clean_name)
    
    # Calculate length
    query_length = len(clean_name)
    
    # Count subdomains
    subdomain_parts = clean_name.split('.')
    subdomain_count = len(subdomain_parts) - 1  # Exclude TLD
    
    # Calculate length of the longest subdomain (where data is often hidden)
    longest_subdomain = max(len(part) for part in subdomain_parts) if subdomain_parts else 0
    
    # Check for base64-like encoding (mixed alphanumeric, possibly with +/)
    # Normal subdomains use lowercase letters and hyphens
    base64_like = bool(re.search(r'[A-Z0-9+/]', clean_name))
    
    # Calculate subdomain entropy (entropy of subdomain part before main domain)
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


def extract_dns_queries(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Extract DNS query records from a list of packets.
    
    Looks for DNS query layers in UDP (port 53) and TCP (port 53) traffic.
    Only processes query (question) records, not responses.
    
    Args:
        packets: List of Scapy packet objects
        
    Returns:
        List of dictionaries containing query info with timestamps
    """
    queries = []
    
    for pkt in packets:
        try:
            # Check for IP layer
            if not pkt.haslayer(IP):
                continue
            
            # Check for DNS traffic (UDP port 53 or TCP port 53)
            is_dns = False
            if pkt.haslayer(UDP) and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
                is_dns = True
            elif pkt.haslayer(TCP) and (pkt[TCP].dport == 53 or pkt[TCP].sport == 53):
                is_dns = True
            
            if not is_dns:
                continue
            
            # Check for DNS layer with query record
            if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
                continue
            
            dns = pkt[DNS]
            dnsqr = pkt[DNSQR]
            
            # Only process queries (opcode 0 = standard query)
            # qr=0 means it's a query, qr=1 means it's a response
            if dns.qr != 0:
                continue
            
            # Extract query name
            query_name = dnsqr.qname
            if isinstance(query_name, bytes):
                query_name = query_name.decode('utf-8', errors='ignore')
            
            if not query_name or query_name == '.':
                continue
            
            # Get query type
            qtype = dnsqr.qtype
            qtype_name = get_query_type_name(qtype)
            
            # Get source and destination IPs
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            queries.append({
                "query_name": query_name.strip('.'),
                "query_type": qtype,
                "query_type_name": qtype_name,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": float(pkt.time)
            })
            
        except Exception:
            # Skip malformed DNS packets
            continue
    
    return queries


def get_query_type_name(qtype: int) -> str:
    """
    Convert DNS query type number to human-readable name.
    
    Common types:
    1=A, 2=NS, 5=CNAME, 6=SOA, 12=PTR, 15=MX, 16=TXT, 28=AAAA, 255=ANY
    
    TXT records are especially suspicious as they carry arbitrary text data.
    
    Args:
        qtype: DNS query type number
        
    Returns:
        Human-readable query type name
    """
    type_names = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
        48: "DNSKEY", 43: "DS", 46: "RRSIG", 47: "NSEC"
    }
    return type_names.get(qtype, f"TYPE{qtype}")


def count_queries_per_domain(queries: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Count how many queries were made to each domain.
    
    High-volume queries to a single domain may indicate automated
    exfiltration through DNS tunneling.
    
    Args:
        queries: List of query dictionaries
        
    Returns:
        Dictionary mapping domain names to query counts
    """
    domain_counts = Counter()
    
    for query in queries:
        domain = extract_domain_from_query(query["query_name"])
        domain_counts[domain] += 1
    
    return dict(domain_counts)


def detect_dns_tunneling(
    pcap_file: str,
    entropy_threshold: float = 3.5,
    length_threshold: int = 50,
    query_count_threshold: int = 20,
    subdomain_entropy_threshold: float = 3.0
) -> List[Dict[str, Any]]:
    """
    Detect DNS tunneling in a PCAP file.
    
    Analyzes DNS queries for multiple indicators of tunneling:
    1. High entropy query names (encoded/encrypted data)
    2. Unusually long query names
    3. High volume of queries to specific domains
    4. TXT record abuse
    
    Args:
        pcap_file: Path to the PCAP file to analyze
        entropy_threshold: Minimum entropy to flag (default 3.5)
        length_threshold: Minimum query length to flag (default 50 chars)
        query_count_threshold: Min queries to a domain to flag (default 20)
        subdomain_entropy_threshold: Min subdomain entropy to flag (default 3.0)
        
    Returns:
        List of dictionaries with tunneling detection results
    """
    findings = []
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[DNS Detector] Error reading PCAP file '{pcap_file}': {e}")
        return findings
    
    if not packets:
        print("[DNS Detector] No packets found in PCAP file.")
        return findings
    
    # Step 1: Extract all DNS queries
    dns_queries = extract_dns_queries(packets)
    
    if not dns_queries:
        print("[DNS Detector] No DNS queries found in PCAP file.")
        return findings
    
    # Step 2: Count queries per domain
    domain_counts = count_queries_per_domain(dns_queries)
    
    # Step 3: Analyze each unique query for tunneling indicators
    analyzed_queries = {}  # Use dict to deduplicate by query name
    
    for query in dns_queries:
        query_name = query["query_name"]
        
        if query_name in analyzed_queries:
            continue
        
        analysis = analyze_dns_query(query_name)
        if not analysis:
            continue
        
        # Add query metadata
        analysis["src_ip"] = query["src_ip"]
        analysis["dst_ip"] = query["dst_ip"]
        analysis["query_type_name"] = query["query_type_name"]
        analysis["domain"] = extract_domain_from_query(query_name)
        analysis["domain_query_count"] = domain_counts.get(analysis["domain"], 1)
        
        analyzed_queries[query_name] = analysis
    
    # Step 4: Flag suspicious queries
    flagged_queries = set()  # Track flagged queries to avoid duplicates
    
    for query_name, analysis in analyzed_queries.items():
        flags = []
        score = 0.0
        
        # Check 1: High entropy (encoded data indicator)
        if analysis["entropy"] >= entropy_threshold:
            flags.append("HIGH_ENTROPY")
            score += (analysis["entropy"] - 3.0) * 20  # Higher entropy = higher score
        
        # Check 2: Long query name (data hiding in subdomains)
        if analysis["query_length"] >= length_threshold:
            flags.append("LONG_QUERY")
            score += (analysis["query_length"] - 40) * 0.5
        
        # Check 3: High subdomain entropy (data in subdomains)
        if analysis["subdomain_entropy"] >= subdomain_entropy_threshold:
            flags.append("HIGH_SUBDOMAIN_ENTROPY")
            score += (analysis["subdomain_entropy"] - 2.5) * 15
        
        # Check 4: Base64-like encoding pattern
        if analysis["base64_like"] and analysis["entropy"] > 3.0:
            flags.append("BASE64_LIKE")
            score += 10
        
        # Check 5: High volume to domain (potential exfiltration)
        if analysis["domain_query_count"] >= query_count_threshold:
            flags.append("HIGH_VOLUME_DOMAIN")
            score += min(analysis["domain_query_count"] / 5, 20)
        
        # Check 6: TXT record queries (commonly abused)
        if analysis["query_type_name"] == "TXT":
            flags.append("TXT_QUERY")
            score += 15
        
        # Check 7: Many subdomains (fragmentation technique)
        if analysis["subdomain_count"] >= 4:
            flags.append("MANY_SUBDOMAINS")
            score += analysis["subdomain_count"] * 3
        
        # Only report if at least one flag triggered
        if flags:
            # Determine severity
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
    
    # Sort by tunnel score (highest first)
    findings.sort(key=lambda x: x["tunnel_score"], reverse=True)
    
    return findings


def format_results(results: List[Dict[str, Any]]) -> str:
    """
    Format DNS tunneling detection results as a readable string.
    
    Args:
        results: List of detection result dictionaries
        
    Returns:
        Formatted string with all findings
    """
    output = []
    output.append("=" * 70)
    output.append("DNS TUNNELING DETECTION RESULTS")
    output.append("=" * 70)
    
    if not results:
        output.append("No suspicious DNS tunneling patterns detected.")
        return "\n".join(output)
    
    output.append(f"Suspicious DNS queries detected: {len(results)}")
    output.append("-" * 70)
    
    for i, result in enumerate(results[:20], 1):  # Show top 20
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
    # Example usage - analyze a PCAP file for DNS tunneling
    import sys
    
    if len(sys.argv) > 1:
        pcap_path = sys.argv[1]
    else:
        print("Usage: python dns_tunnel_detector.py <pcap_file>")
        print("\nExample:")
        print("  python dns_tunnel_detector.py /path/to/capture.pcap")
        print("\nThis will analyze the PCAP for DNS tunneling patterns.")
        sys.exit(1)
    
    print(f"[*] Analyzing {pcap_path} for DNS tunneling...")
    results = detect_dns_tunneling(pcap_path)
    print(format_results(results))
