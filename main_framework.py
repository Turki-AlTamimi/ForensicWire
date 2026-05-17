#!/usr/bin/env python3
"""
================================================================================
Malicious Network Behavior Detection Framework
================================================================================
Digital Forensics Course Project - Main Controller Module

This is the main controller for the Malicious Network Behavior Detection
Framework. It orchestrates three detection modules:

1. C2 Beaconing Detection    (c2_detector.py) - Detects command & control
2. DNS Tunneling Detection   (dns_tunnel_detector.py) - Detects DNS tunnels
3. Data Exfiltration Detection (exfil_detector.py) - Detects data theft

Usage:
    python main_framework.py <pcap_file> [options]
    
    Options:
        --output <file>     Save JSON report to file
        --format <format>   Output format: text (default) or json
        --summary           Show only summary, not details
        
    Example:
        python main_framework.py capture.pcap
        python main_framework.py capture.pcap --output report.json --format json

Framework Output:
    - Structured report with all findings from all modules
    - Severity ratings (HIGH, MEDIUM, LOW) for each finding
    - Risk scores for prioritization
    - Detailed evidence for each detection
================================================================================
"""

import argparse
import json
import sys
import time
from datetime import datetime
from typing import Dict, Any, List

# Import detection modules
import c2_detector
import dns_tunnel_detector
import exfil_detector


def run_all_detections(pcap_file: str) -> Dict[str, Any]:
    """
    Run all three detection modules on a PCAP file.
    
    This function orchestrates the analysis by calling each detection module
    and collecting their results into a unified structure.
    
    Detection pipeline:
    1. C2 Beaconing Detection - identifies periodic C2 communications
    2. DNS Tunneling Detection - identifies DNS-based covert channels
    3. Data Exfiltration Detection - identifies unauthorized data transfers
    
    Args:
        pcap_file: Path to the PCAP file to analyze
        
    Returns:
        Dictionary containing results from all modules and a summary
    """
    results = {
        "metadata": {
            "pcap_file": pcap_file,
            "analysis_time": datetime.now().isoformat(),
            "framework_version": "1.0.0",
            "modules_run": [
                "c2_beaconing_detection",
                "dns_tunneling_detection", 
                "data_exfiltration_detection"
            ]
        },
        "findings": {
            "c2_beaconing": [],
            "dns_tunneling": [],
            "data_exfiltration": []
        },
        "summary": {}
    }
    
    # --- Module 1: C2 Beaconing Detection ---
    print("[*] Running C2 Beaconing Detection...")
    try:
        start_time = time.time()
        c2_results = c2_detector.detect_beaconing(pcap_file)
        elapsed = time.time() - start_time
        results["findings"]["c2_beaconing"] = c2_results
        print(f"    [+] Found {len(c2_results)} suspicious beaconing patterns "
              f"({elapsed:.2f}s)")
    except Exception as e:
        print(f"    [-] C2 detection failed: {e}")
        results["findings"]["c2_beaconing"] = []
    
    # --- Module 2: DNS Tunneling Detection ---
    print("[*] Running DNS Tunneling Detection...")
    try:
        start_time = time.time()
        dns_results = dns_tunnel_detector.detect_dns_tunneling(pcap_file)
        elapsed = time.time() - start_time
        results["findings"]["dns_tunneling"] = dns_results
        print(f"    [+] Found {len(dns_results)} suspicious DNS queries "
              f"({elapsed:.2f}s)")
    except Exception as e:
        print(f"    [-] DNS tunneling detection failed: {e}")
        results["findings"]["dns_tunneling"] = []
    
    # --- Module 3: Data Exfiltration Detection ---
    print("[*] Running Data Exfiltration Detection...")
    try:
        start_time = time.time()
        exfil_results = exfil_detector.detect_exfiltration(pcap_file)
        elapsed = time.time() - start_time
        results["findings"]["data_exfiltration"] = exfil_results
        print(f"    [+] Found {len(exfil_results)} suspicious exfiltration patterns "
              f"({elapsed:.2f}s)")
    except Exception as e:
        print(f"    [-] Exfiltration detection failed: {e}")
        results["findings"]["data_exfiltration"] = []
    
    # --- Generate Summary ---
    results["summary"] = generate_summary(results["findings"])
    
    return results


def generate_summary(findings: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """
    Generate a summary of all detection findings.
    
    Counts findings by module and severity to give an overview of
    the detection results.
    
    Args:
        findings: Dictionary with findings from each module
        
    Returns:
        Summary dictionary with counts and risk assessment
    """
    summary = {
        "total_findings": 0,
        "by_module": {},
        "by_severity": {
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        },
        "risk_assessment": ""
    }
    
    for module_name, module_findings in findings.items():
        count = len(module_findings)
        summary["by_module"][module_name] = count
        summary["total_findings"] += count
        
        for finding in module_findings:
            severity = finding.get("severity", "LOW")
            if severity in summary["by_severity"]:
                summary["by_severity"][severity] += 1
    
    # Overall risk assessment
    high_count = summary["by_severity"]["HIGH"]
    medium_count = summary["by_severity"]["MEDIUM"]
    
    if high_count >= 3:
        summary["risk_assessment"] = "CRITICAL - Multiple high-severity threats detected"
    elif high_count >= 1:
        summary["risk_assessment"] = "HIGH - Significant malicious activity detected"
    elif medium_count >= 2:
        summary["risk_assessment"] = "MEDIUM - Suspicious activity warrants investigation"
    elif summary["total_findings"] > 0:
        summary["risk_assessment"] = "LOW - Minor anomalies detected"
    else:
        summary["risk_assessment"] = "CLEAN - No malicious patterns detected"
    
    return summary


def format_text_report(results: Dict[str, Any], show_details: bool = True) -> str:
    """
    Format detection results as a human-readable text report.
    
    Args:
        results: Complete detection results dictionary
        show_details: Whether to include detailed findings or just summary
        
    Returns:
        Formatted text report string
    """
    lines = []
    meta = results["metadata"]
    summary = results["summary"]
    
    # Header
    lines.append("\n" + "=" * 78)
    lines.append("  MALICIOUS NETWORK BEHAVIOR DETECTION FRAMEWORK - ANALYSIS REPORT")
    lines.append("=" * 78)
    lines.append(f"\n  PCAP File:     {meta['pcap_file']}")
    lines.append(f"  Analysis Time: {meta['analysis_time']}")
    lines.append(f"  Framework:     v{meta['framework_version']}")
    
    # Summary
    lines.append(f"\n{'─' * 78}")
    lines.append("  EXECUTIVE SUMMARY")
    lines.append("─" * 78)
    lines.append(f"  Risk Assessment: {summary['risk_assessment']}")
    lines.append(f"  Total Findings:  {summary['total_findings']}")
    lines.append(f"\n  By Severity:")
    lines.append(f"    HIGH:   {summary['by_severity']['HIGH']:>3} findings")
    lines.append(f"    MEDIUM: {summary['by_severity']['MEDIUM']:>3} findings")
    lines.append(f"    LOW:    {summary['by_severity']['LOW']:>3} findings")
    lines.append(f"\n  By Module:")
    for module, count in summary['by_module'].items():
        lines.append(f"    {module:<25} {count:>3} findings")
    
    # Detailed findings
    if show_details and summary['total_findings'] > 0:
        lines.append(f"\n{'=' * 78}")
        
        # C2 Beaconing
        c2_findings = results["findings"]["c2_beaconing"]
        if c2_findings:
            lines.append(f"\n{'─' * 78}")
            lines.append("  MODULE 1: C2 BEACONING DETECTION")
            lines.append("─" * 78)
            lines.append(f"  Found {len(c2_findings)} suspicious beaconing patterns")
            lines.append("")
            
            for i, f in enumerate(c2_findings[:15], 1):
                lines.append(f"  [{i}] Severity: {f['severity']} | "
                           f"Score: {f['beacon_score']}/100")
                lines.append(f"      Connection: {f['src_ip']} -> "
                           f"{f['dst_ip']}:{f['dst_port']}")
                lines.append(f"      Packets: {f['packet_count']} | "
                           f"CV: {f['coefficient_of_variation']} | "
                           f"Interval: {f['mean_interval_seconds']}s")
                lines.append("")
        
        # DNS Tunneling
        dns_findings = results["findings"]["dns_tunneling"]
        if dns_findings:
            lines.append(f"\n{'─' * 78}")
            lines.append("  MODULE 2: DNS TUNNELING DETECTION")
            lines.append("─" * 78)
            lines.append(f"  Found {len(dns_findings)} suspicious DNS queries")
            lines.append("")
            
            for i, f in enumerate(dns_findings[:15], 1):
                lines.append(f"  [{i}] Severity: {f['severity']} | "
                           f"Score: {f['tunnel_score']}/100")
                lines.append(f"      Query: {f['query_name']}")
                lines.append(f"      Source: {f['src_ip']} -> DNS: {f['dst_ip']}")
                lines.append(f"      Entropy: {f['entropy']} | "
                           f"Length: {f['query_length']} chars | "
                           f"Type: {f['query_type']}")
                lines.append(f"      Flags: {', '.join(f['flags'])}")
                lines.append("")
        
        # Data Exfiltration
        exfil_findings = results["findings"]["data_exfiltration"]
        if exfil_findings:
            lines.append(f"\n{'─' * 78}")
            lines.append("  MODULE 3: DATA EXFILTRATION DETECTION")
            lines.append("─" * 78)
            lines.append(f"  Found {len(exfil_findings)} suspicious exfiltration patterns")
            lines.append("")
            
            for i, f in enumerate(exfil_findings[:15], 1):
                lines.append(f"  [{i}] Severity: {f['severity']} | "
                           f"Score: {f['exfil_score']}/100")
                lines.append(f"      Connection: {f['internal_ip']} -> "
                           f"{f['external_ip']}")
                lines.append(f"      Outbound: {f['outbound_bytes']:,} bytes "
                           f"| Inbound: {f['inbound_bytes']:,} bytes")
                lines.append(f"      O/I Ratio: {f['oi_ratio']} | "
                           f"Duration: {f['duration_seconds']}s")
                lines.append(f"      Protocols: {', '.join(f['protocols'])} | "
                           f"Flags: {', '.join(f['flags'])}")
                lines.append("")
    
    # Footer
    lines.append(f"\n{'=' * 78}")
    lines.append("  END OF REPORT")
    lines.append("=" * 78 + "\n")
    
    return "\n".join(lines)


def format_json_report(results: Dict[str, Any]) -> str:
    """
    Format detection results as a JSON report.
    
    Args:
        results: Complete detection results dictionary
        
    Returns:
        Formatted JSON string
    """
    return json.dumps(results, indent=2, default=str)


def save_report(report: str, output_file: str) -> bool:
    """
    Save the report to a file.
    
    Args:
        report: Report content string
        output_file: Path to output file
        
    Returns:
        True if saved successfully, False otherwise
    """
    try:
        with open(output_file, 'w') as f:
            f.write(report)
        return True
    except IOError as e:
        print(f"[-] Error saving report to {output_file}: {e}")
        return False


def main():
    """
    Main entry point for the framework.
    
    Parses command-line arguments and runs the detection pipeline.
    """
    parser = argparse.ArgumentParser(
        description="Malicious Network Behavior Detection Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main_framework.py capture.pcap
  python main_framework.py capture.pcap --output report.json --format json
  python main_framework.py capture.pcap --summary

Modules:
  - C2 Beaconing Detection: Identifies periodic C2 communication patterns
  - DNS Tunneling Detection: Identifies DNS-based covert channels
  - Data Exfiltration Detection: Identifies unauthorized data transfers
        """
    )
    
    parser.add_argument(
        "pcap_file",
        help="Path to the PCAP file to analyze"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save report to file (default: print to console)"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Report format: text (default) or json"
    )
    parser.add_argument(
        "--summary", "-s",
        action="store_true",
        help="Show only summary, not detailed findings"
    )
    
    args = parser.parse_args()
    
    # Validate PCAP file
    import os
    if not os.path.isfile(args.pcap_file):
        print(f"[-] Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("  MALICIOUS NETWORK BEHAVIOR DETECTION FRAMEWORK")
    print("=" * 70)
    print(f"\n[*] Starting analysis of: {args.pcap_file}")
    print(f"[*] Report format: {args.format}")
    print(f"[*] Details: {'Summary only' if args.summary else 'Full report'}")
    
    # Run all detection modules
    start_time = time.time()
    results = run_all_detections(args.pcap_file)
    total_time = time.time() - start_time
    
    print(f"\n[*] Analysis completed in {total_time:.2f} seconds")
    
    # Format report
    if args.format == "json":
        report = format_json_report(results)
    else:
        report = format_text_report(results, show_details=not args.summary)
    
    # Output report
    if args.output:
        if save_report(report, args.output):
            print(f"[+] Report saved to: {args.output}")
    else:
        print(report)
    
    # Return exit code based on findings
    high_count = results["summary"]["by_severity"]["HIGH"]
    if high_count > 0:
        sys.exit(1)  # Exit with error code if high-severity findings
    sys.exit(0)


if __name__ == "__main__":
    # Example usage:
    #   python main_framework.py capture.pcap
    #   python main_framework.py capture.pcap --output report.txt
    #   python main_framework.py capture.pcap --format json --output report.json
    main()
