# Section I: Title Page

**Project Proposal: Malicious Network Behavior Detection Framework**

---

| **Name** | Turki AL-Tamimi |
|---|---|
| **Course** | Digital Forensics |
| **Instructor** | Ehab AlNfrawy |
| **Academic Year** | 2025–2026 |

---

## Brief Project Summary

This project develops a Python-based network forensic framework using free, browser-based tools to detect Command and Control (C2) beaconing, DNS tunneling, and data exfiltration patterns. The framework integrates multiple detection algorithms to provide an accessible, unified solution for network traffic analysis in educational and resource-limited environments.

---

# Section II: Problem Statement

Modern malware employs sophisticated network techniques that pose substantial challenges for digital forensic investigators. Advanced Persistent Threat (APT) groups routinely utilize Command and Control (C2) beaconing—periodic communication between compromised hosts and attacker-controlled servers—to maintain persistent access. Furthermore, malicious actors exploit the Domain Name System (DNS) protocol to establish covert channels through DNS tunneling, leveraging tools such as Iodine and dnscat2 to encapsulate data within legitimate DNS queries. Combined with covert data exfiltration methods that fragment stolen information within encrypted protocols such as HTTPS, these techniques enable attackers to evade conventional intrusion detection systems that rely on static signatures [^1^].

A significant limitation in the current landscape is the reliance on expensive commercial solutions that remain inaccessible to educational institutions and small organizations with constrained budgets. While browser-based and open-source tools such as CloudShark and Wireshark provide capable platforms for individual packet inspection, they lack integrated frameworks that consolidate multiple detection capabilities into a unified system [^2^]. Existing detection approaches typically focus on isolated techniques; single-packet methods analyzing DNS payload features suffer from high false alarm rates, while grouped-packet approaches are computationally demanding and unsuitable for real-time inspection [^2^]. The absence of a cohesive, freely available detection framework leaves a critical gap for emerging forensic analysts.

Network forensics serves as a foundational discipline within incident response and malware investigation. The development of an integrated framework using accessible tools would address a pressing need: the global average cost of a data breach reached USD 4.88 million in 2024, with C2-enabled attacks contributing substantially to this figure [^3^]. By consolidating detection algorithms for C2 traffic, DNS tunneling, and data exfiltration into a single Python-based framework, this project aims to bridge the accessibility gap in network forensic tools, supporting both digital forensics education and the defensive needs of budget-constrained organizations.

---


---

## III. Objectives and Scope

The primary objective is to develop a Python-based detection framework that analyzes PCAP files to identify command-and-control (C2) beaconing patterns, DNS tunneling attempts, and data exfiltration activities. Following SMART criteria, the framework will comprise modular detection engines—one per threat category—each producing standardized output with severity-based alerting. The framework will be validated against publicly available datasets, including CICIDS2017, which contains labeled network traffic encompassing botnet and infiltration behaviors[^1^].

Secondary objectives include integrating browser-based analysis tools (e.g., CloudShark) for visual confirmation, documenting the forensic methodology per the ACPO Good Practice Guide for Digital Evidence[^2^], and developing a user-friendly reporting module.

The project scope is intentionally bounded to network layer analysis (Layers 3–7) using exclusively free and open-source tools. The framework operates on existing PCAP captures rather than real-time traffic, employing statistical and behavioral analysis techniques rather than machine learning approaches. Detection is explicitly limited to the three specified threat categories.

**Deliverables** include: (1) a functional Python detection framework with three modular components; (2) validated test results against sample datasets; and (3) a comprehensive final report documenting the forensic methodology.


---

## IV. Methodology and Technical Approach

This section delineates the systematic methodology employed to develop a framework for detecting malicious network behaviors, specifically command-and-control (C2) traffic, DNS tunneling, and data exfiltration patterns. The approach integrates publicly available datasets, browser-based packet inspection tools, statistical analysis techniques, and controlled laboratory experimentation to ensure reproducibility and rigor.

### 1. Data Acquisition Phase

The foundation of any forensic investigation rests upon the integrity and provenance of the acquired evidence. Accordingly, this project utilizes three established, publicly available network intrusion datasets: the CICIDS2017 dataset, which provides labeled benign and attack traffic including botnet, DoS, and infiltration scenarios captured over five days of network activity [^1^]; the CTU-13 dataset, containing thirteen distinct botnet traffic captures with ground-truth labels suitable for botnet detection evaluation [^2^]; and the Stratosphere IPS datasets, which offer labeled malicious traffic for behavioral analysis research. Initial inspection of all Packet Capture (PCAP) files is conducted using browser-based analysis platforms, namely CloudShark and PacketTotal, enabling rapid protocol distribution review, display filtering, and preliminary anomaly identification without local software installation. To supplement public datasets, controlled test scenarios are executed within isolated virtual machine environments using tools such as Wireshark, Python/scapy, and DNS tunneling utilities (e.g., iodine, dnscat2) to generate synthetic C2 beaconing, DNS tunneling, and data exfiltration traffic. All evidence files are documented with comprehensive chain-of-custody records, including SHA-256 hash values, acquisition timestamps, source URLs, and storage locations to maintain forensic admissibility.

### 2. Detection Methodology

The analytical framework comprises three independent detection modules, each targeting a specific category of malicious network behavior.

**Module 1: C2 Traffic Detection.** Command-and-control communications frequently exhibit distinctive temporal patterns known as beaconing. This module analyzes inter-packet arrival times to identify connections characterized by highly regular periodicity. Long-running TCP or UDP sessions transmitting small, consistent payloads at fixed intervals are flagged for further investigation. Statistical analysis computes the coefficient of variation of inter-arrival times; connections demonstrating low variation alongside sustained low-data-volume transmission are assigned elevated risk scores as potential C2 channels.

**Module 2: DNS Tunneling Detection.** DNS tunneling exploits the DNS protocol to encapsulate non-DNS data within query and response packets. This module employs Shannon entropy calculation to quantify the randomness of DNS query names, where elevated entropy values indicate potentially encoded or encrypted tunnel traffic [^3^]. Additional detection heuristics include monitoring for unusually large DNS query or response payloads (exceeding typical ~60 byte query lengths), identifying excessive query volumes directed at specific domains, analyzing subdomain length distributions and character patterns, and detecting Base32, Base64, or hexadecimal encoding signatures within DNS labels. These indicators, when correlated, provide robust evidence of DNS tunneling activity [^4^].

**Module 3: Data Exfiltration Detection.** Unauthorized data transfer is identified through volumetric and temporal anomaly detection. This module monitors outbound data volumes per connection, flagging transfers that exceed statistically derived thresholds or target external, non-standard destinations. Off-hours data transfers occurring outside established organizational activity windows are prioritized for review. Protocol misuse detection identifies protocols typically used for control rather than bulk data transfer (e.g., DNS, ICMP) carrying anomalous payload sizes. A key metric is the outbound-to-inbound data ratio; connections exhibiting significantly higher outbound than inbound volume receive elevated risk scores indicative of potential exfiltration.

### 3. Validation and Verification

Detection efficacy is validated against labeled datasets containing known malicious traffic instances. Each module's output is cross-validated using multiple complementary detection methods to reduce false positives. Browser-based tools, particularly CloudShark, provide visual confirmation of flagged traffic patterns through timeline graphs, protocol hierarchy statistics, and packet-level inspection. Detection accuracy is quantified using standard metrics: true positive rate (TPR/recall), false positive rate (FPR), precision, and F1-score. Confusion matrices are generated for each module to assess performance across different attack categories.

### 4. Reporting

The framework generates structured JSON reports for each detected anomaly, containing the detection timestamp, source and destination IP addresses and ports, the detection module and specific method triggered, a normalized confidence score (0.0–1.0), and a severity classification (low, medium, high, critical). Reports are designed for compatibility with browser-based visualization tools, enabling import into CloudShark for annotated review and evidence presentation suitable for both technical stakeholders and legal proceedings.

### Tool Comparison

| Tool | Type | Cost | Key Capabilities | Role in Framework |
|------|------|------|------------------|-------------------|
| CloudShark | Browser-based PCAP analyzer | Free tier available | Display filtering, protocol analysis, traffic graphs, URL-based sharing | Primary inspection and visual validation |
| PacketTotal | Browser-based PCAP analyzer | Free | Automated threat detection, Suricata/Snort rule matching, static analysis | Initial automated threat screening |
| Wireshark | Desktop packet analyzer | Free (open source) | Deep packet inspection, expert info, I/O graphing | Detailed packet-level forensics |
| Python/scapy | Packet manipulation library | Free (open source) | Programmable packet crafting, custom protocol analysis, statistical extraction | Automated detection script development |

---

## V. Resources and Requirements

### Technical Requirements

This project requires a standard computer with a minimum of 8GB RAM to process voluminous PCAP files without performance degradation, alongside at least 50GB of free storage for datasets and intermediate analysis artifacts. The software stack comprises Python 3.8 or later, augmented by scapy for low-level packet manipulation, pyshark as a Pythonic wrapper around tshark, dpkt for fast packet parsing, numpy for numerical computation, and matplotlib for data visualization [^1^].

For packet inspection, the project will utilize CloudShark as an online PCAP analyzer, supplemented by PacketTotal and Wireshark for complementary desktop and browser-based analysis. Google Colab will provide a cloud-based execution environment for computationally intensive scripts. The recommended operating system is Kali Linux, given its preinstalled forensic and penetration testing utilities; alternatively, Windows with WSL provides a viable platform [^2^].

### Data Sources

The analytical framework will be validated against publicly available benchmark datasets, including the CICIDS2017 dataset from the Canadian Institute for Cybersecurity, the CTU-13 botnet traffic corpus from Czech Technical University, and Stratosphere IPS datasets. Supplementary malicious traffic samples will be sourced from the Contagio malware dump. Self-generated traffic will be produced using virtual machines leveraging the Metasploit Framework for C2 simulation, iodine and dnscat2 for DNS tunneling emulation, and custom Python scripts to model data exfiltration behaviors.

### Sample Evidence Files

The project will utilize labeled PCAP files containing known malicious traffic patterns, network traffic logs exported in CSV format, and DNS query logs curated for tunneling detection evaluation. These evidence files will serve as both training inputs and validation benchmarks throughout the development lifecycle.

# Section VI: Expected Outcomes and Impact

This project is anticipated to yield a functional Python-based framework capable of detecting command-and-control (C2) traffic, DNS tunneling, and data exfiltration patterns with measurable accuracy[^1^][^2^]. Through systematic analysis of network traffic captures using CloudShark and Wireshark-compatible tools, the framework will identify key behavioral indicators for each threat category, including beaconing periodicity and jitter patterns for C2 detection, query frequency anomalies and payload entropy for DNS tunneling identification, and volume-based thresholds for data exfiltration recognition[^3^][^4^]. A comparative analysis of detection effectiveness across different traffic types will validate the framework's utility, with results quantifying true positive and false positive rates against publicly available datasets such as CICIDS2017[^5^]. The contribution to the digital forensics community includes a free, open-source tool designed specifically for educational use in academic programs, following the ACPO principles for digital evidence handling[^1^]. Its modular architecture allows for straightforward extension to additional threat types, making it a practical resource for small organizations with limited security budgets. Future expansion pathways include the integration of supervised and unsupervised machine learning algorithms for improved detection accuracy[^4^], real-time analysis capability through streaming packet capture, additional modules for detecting covert channels and protocol abuse, and integration with Security Information and Event Management (SIEM) platforms to enhance enterprise security operations[^2^].

# Section VII: Legal and Ethical Considerations

This project adheres strictly to the Association of Chief Police Officers (ACPO) Good Practice Guide for Digital Evidence (2012), ensuring compliance with all four core principles[^1^]. Principle 1 is satisfied through read-only analysis of captured network traffic, ensuring no data is modified that may be relied upon as evidence. Principle 2 is maintained by restricting analysis to competent personnel with appropriate forensic training. Principle 3 requires comprehensive audit trail creation, which the framework achieves through automated logging of all processing steps and preserved outputs. Principle 4 places responsibility on the investigation lead to ensure adherence to legal standards and ACPO principles throughout all phases[^1^]. Privacy and data protection considerations mandate the exclusive use of publicly available datasets, such as CICIDS2017, and self-generated laboratory traffic[^5^]. No private network data is analyzed without explicit authorization. All data handling complies with institutional policies and applicable privacy regulations, including GDPR considerations for any data processing activities[^1^]. Authorization and chain of custody protocols require that all datasets be obtained solely from legitimate public sources, with thorough documentation of data provenance. Evidence integrity is verified through SHA-256 hash validation of all capture files, and all evidence materials are stored in secure, access-controlled environments to maintain continuity and admissibility[^1^][^6^].
