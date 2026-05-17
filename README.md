# NetSpecter

> **Python-based network forensic framework for detecting C2 beaconing, DNS tunneling, and data exfiltration in PCAP captures.**

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()

---

## Overview

NetSpecter is a modular, open-source network forensic analysis framework designed to detect three critical classes of malicious network behavior from packet capture (PCAP) files:

- **C2 Beaconing** — periodic command-and-control communication patterns
- **DNS Tunneling** — covert data channels over DNS queries
- **Data Exfiltration** — unauthorized outbound data transfers

Built for **educational environments**, **CTF competitions**, and **resource-limited organizations**, NetSpecter consolidates multiple detection algorithms into a unified, extensible Python toolkit. It operates entirely on existing PCAP captures using statistical and heuristic analysis — no machine learning dependencies, no expensive commercial tools.

---

## Features

| Module | Detection Method | Output |
|--------|-----------------|--------|
| **C2 Beaconing Detector** | Inter-packet arrival time analysis, coefficient of variation, payload consistency | Risk-scored connection profiles |
| **DNS Tunneling Detector** | Shannon entropy of query names, payload size heuristics, encoding pattern detection (Base32/64, hex), subdomain analysis | Confidence-rated anomaly reports |
| **Data Exfiltration Detector** | Volume thresholds, outbound/inbound ratio analysis, off-hours transfer detection, protocol misuse identification | Severity-classified alerts |

**Additional capabilities:**
- JSON-structured forensic reports with severity classification (`low` → `critical`)
- SHA-256 chain-of-custody verification for evidence integrity
- CloudShark-compatible report export for browser-based visual validation
- Modular architecture — add new detection engines with minimal boilerplate

---

## Quick Start

### Prerequisites

- Python 3.8+
- 8 GB RAM minimum (for large PCAP processing)
- 50 GB free storage (datasets + artifacts)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netspecter.git
cd netspecter

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Analyze a single PCAP file
python netspecter.py --pcap sample_traffic.pcap --output report.json

# Run specific detection modules
python netspecter.py --pcap sample_traffic.pcap --modules c2,dns,exfil

# Generate verbose report with packet-level details
python netspecter.py --pcap sample_traffic.pcap --verbose --format json
```

### Example Output

```json
{
  "analysis_timestamp": "2026-05-17T14:39:00Z",
  "file_hash_sha256": "a3f5c2...",
  "detections": [
    {
      "module": "c2_beaconing",
      "severity": "high",
      "confidence": 0.87,
      "src_ip": "192.168.1.105",
      "dst_ip": "185.220.101.42",
      "indicators": {
        "interval_cv": 0.04,
        "session_duration_min": 142,
        "avg_payload_bytes": 512
      }
    }
  ]
}
```

---

## Architecture

```
netspecter/
├── core/
│   ├── engine.py          # Orchestration layer
│   └── evidence.py        # Chain-of-custody & hashing
├── modules/
│   ├── c2_detector.py     # Beaconing analysis
│   ├── dns_detector.py    # Tunneling detection
│   └── exfil_detector.py  # Data exfiltration
├── utils/
│   ├── pcap_parser.py     # scapy/dpkt wrappers
│   └── report_generator.py # JSON/CSV export
├── datasets/              # Sample PCAPs & labels
├── tests/                 # Unit & integration tests
└── docs/                  # Methodology & API reference
```

---

## Validation Datasets

NetSpecter is validated against publicly available benchmark datasets:

| Dataset | Source | Use Case |
|---------|--------|----------|
| [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Canadian Institute for Cybersecurity | Botnet & infiltration traffic |
| [CTU-13](https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/) | Czech Technical University | Botnet detection evaluation |
| [Stratosphere IPS](https://www.stratosphereips.org/datasets-overview) | Stratosphere Lab | Behavioral analysis research |

---

## Methodology

This framework follows the **ACPO Good Practice Guide for Digital Evidence** (2012):

1. **Principle 1** — Read-only analysis; no modification of original evidence
2. **Principle 2** — Competent personnel with forensic training
3. **Principle 3** — Comprehensive automated audit trails
4. **Principle 4** — Investigation lead accountability

All datasets are sourced exclusively from legitimate public repositories or self-generated in isolated lab environments. No private network data is analyzed without explicit authorization.

---

## Roadmap

- [ ] Real-time streaming analysis (live capture)
- [ ] Machine learning integration (supervised/unsupervised)
- [ ] SIEM platform connectors (Splunk, ELK)
- [ ] Covert channel & protocol abuse modules
- [ ] Web-based dashboard for report visualization

---

## Contributing

Contributions are welcome. Please open an issue for bug reports or feature requests, and submit pull requests against the `main` branch.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- Built as part of the **Digital Forensics** course at University of Hail, Academic Year 2025–2026
- Instructor: **Ehab AlNfrawy**
- Detection methodologies informed by research from Sharafaldin et al. (CICIDS2017), Garcia et al. (CTU-13), and Tu et al. (DNS tunneling detection)
