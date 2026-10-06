# 🛡️ CTF Blue Team & DFIR Operations Toolkit

A high-performance, modular suite of Python-based security tools engineered for Blue Team CTF competitions, Digital Forensics and Incident Response (DFIR), system hardening, and infrastructure defense.

Designed for rapid deployment during high-stress defensive operations, these tools operate with minimal or zero external dependencies (standard Python 3 library) to guarantee immediate execution across pristine, air-gapped, or compromised hosts.

---

## 📑 Table of Contents

- [Overview & Architecture](#-overview--architecture)
- [Tool Catalog by Category](#-tool-catalog-by-category)
  - [1. Live DFIR & Digital Forensics](#1-live-dfir--digital-forensics)
  - [2. SIEM, Threat Detection & Log Analysis](#2-siem-threat-detection--log-analysis)
  - [3. Host Defense, Hardening & Persistence Hunting](#3-host-defense-hardening--persistence-hunting)
  - [4. Service Resilience & Restoration](#4-service-resilience--restoration)
  - [5. CTF Operations, Scoring & Reporting](#5-ctf-operations-scoring--reporting)
  - [6. Cryptography, Encodings & Flag Hunting](#6-cryptography-encodings--flag-hunting)
- [Repository Structure](#-repository-structure)
- [Prerequisites & Quick Start](#-prerequisites--quick-start)
- [Detailed Tool Reference](#-detailed-tool-reference)
- [Operational Safety & Disclaimer](#-operational-safety--disclaimer)

---

## 🏛️ Overview & Architecture

Defensive security and CTF blue teaming require rapid triage, evidence preservation, threat isolation, and service restoration under strict operational constraints. This toolkit solves these challenges with specialized, standalone modules categorized across the entire incident lifecycle:

```
[ Compromise / Alert ] ──► dfir_triage & pcap_analyzer (Volatile Collection)
          │
          ├──► log_analyzer & log_timeline (Event Reconstruction)
          │
          ├──► ioc_hunter & SIEM Builders (Elastic / Splunk Correlation)
          │
          ├──► vuln_patcher, firewall_manager & web_config_auditor (Containment)
          │
          ├──► service_doctor & cod_fixer (Service Restoration)
          │
          └──► report_builder & submission_tracker (IoC / IR Scoring)
```

---

## 🗂️ Tool Catalog by Category

| Category | Directory | Primary Tool | Description |
|---|---|---|---|
| **Live DFIR** | [`dfir_triage/`](dfir_triage/) | `dfir_triage.py` | Rapid volatile state triage, active connections, deleted binary execution, and cron dumping. |
| **Forensics** | [`ad1_parser/`](ad1_parser/) | `ad1_parser.py` | Streaming AccessData FTK Logical Image (`.ad1`) parser, searcher, and extractor without mounting. |
| **Forensics** | [`artifact_hunter/`](artifact_hunter/) | `artifact_hunter.py` | Sweeps targets for high-value artifacts, SSH keys, AWS credentials, browser DBs, and secrets. |
| **Forensics** | [`evidence_collector/`](evidence_collector/) | `evidence_collector.py` | Structured evidence acquisition, cryptographic hashing (MD5/SHA256), and chain of custody. |
| **Forensics** | [`pcap_analyzer/`](pcap_analyzer/) | `pcap_analyzer.py` | Pure-Python packet capture analysis (sessions, DNS, HTTP, cleartext credentials). |
| **Forensics** | [`stego_triage/`](stego_triage/) | `stego_triage.py` | Steganography file triage (magic bytes, appended data, LSB channels, strings). |
| **Detection** | [`ioc_hunter/`](ioc_hunter/) | `ioc_extract.py` | High-speed IoC extractor for IPv4, IPv6, domains, URLs, hashes, CVEs, and emails. |
| **Detection** | [`log_analyzer/`](log_analyzer/) | `log_analyzer.py` | Web and authentication log parser; flags brute-force, web attacks (SQLi/XSS), and anomalies. |
| **Detection** | [`log_timeline/`](log_timeline/) | `log_timeline.py` | Multi-source log normalizer aggregating disparate logs into a unified chronological timeline. |
| **Detection** | [`elastic_siem/`](elastic_siem/) | `elastic_query_builder.py` | Interactive KQL, EQL, and Lucene query generator with MITRE ATT&CK templates. |
| **Detection** | [`splunk_siem/`](splunk_siem/) | `splunk_query_builder.py` | Interactive Splunk SPL query generator for IR, authentication, and lateral movement. |
| **Hardening** | [`firewall_manager/`](firewall_manager/) | `firewall_manager.py` | Rapid host firewall management (iptables/ufw/nftables) for emergency lockdown and port allowlisting. |
| **Hardening** | [`vuln_patcher/`](vuln_patcher/) | `vuln_patcher.py` | Automated vulnerability auditing and remediation (SUID, sudoers, cron, SSH configs). |
| **Hardening** | [`web_config_auditor/`](web_config_auditor/) | `web_config_auditor.py` | Offline config auditing & webshell scanner for Nginx, PHP, MySQL, Postgres, GitLab, Roundcube. |
| **Defense** | [`persistence_hunter/`](persistence_hunter/) | `persistence_hunter.py` | Deep audit of Linux persistence mechanisms (cron, systemd, rc.local, shell profiles, SUIDs). |
| **Restoration** | [`service_doctor/`](service_doctor/) | `service_doctor.py` | Automated daemon health check, systemd triage, log diagnostic, and recovery. |
| **Restoration** | [`service_restoration/`](service_restoration/) | `baseline_diff.py` | Filesystem baseline snapshotting and diffing to identify tampered or injected files. |
| **Restoration** | [`cod_fixer/`](cod_fixer/) | `code_doctor.py` | Auto-repairs broken syntax, BOM markers, CRLF endings, and indentation in downed services. |
| **Operations** | [`submission_tracker/`](submission_tracker/) | `submission_tracker.py` | State-machine tracker for IoCs and reports; prevents rule violations and limits breaches. |
| **Operations** | [`score_calculator/`](score_calculator/) | `score_calculator.py` | CTF scoring modeler and point optimization calculator (SLA × Task + IoCs). |
| **Operations** | [`report_builder/`](report_builder/) | `report_builder.py` | Generates professional Incident Response reports with timelines and verified IoC tables. |
| **Recon & Net** | [`scan/`](scan/) | `proc_tree.py`, `net_map.py` | Process hierarchy visualization with listening sockets; subnet host discovery. |
| **Crypto & CTF**| [`hash_toolkit/`](hash_toolkit/) | `hash_toolkit.py` | Multi-hash generation, hash type identification, and wordlist verification. |
| **Crypto & CTF**| [`encoding_decoder/`](encoding_decoder/) | `encoding_decoder.py` | Multi-layer recursive decoder (Base64, Hex, URL, Binary, ROT13, XOR). |
| **Crypto & CTF**| [`zip_extracter/`](zip_extracter/) | `zipcrypto_helper.py` | Encrypted ZIP archive triage, known-plaintext generation, and bkcrack command helper. |
| **Crypto & CTF**| [`flag_hunnter/`](flag_hunnter/) | `flag_hunter.py`, `entropy_scan.py`| Flag hunter across files/dumps; Shannon entropy scanner to locate encrypted/packed payloads. |

---

## 🚀 Prerequisites & Quick Start

### Prerequisites
- Python 3.8 or higher.
- Standard Linux utilities (`iptables`, `systemctl`, `ss`/`netstat` when running host-level audits).
- No third-party packages required for core tools (uses Python Standard Library).

### Installation
Clone the repository and set appropriate permissions:

```bash
git clone https://github.com/<username>/<repo>.git
cd <repo>
chmod +x */*.py
```

---

## 📖 Detailed Tool Reference

### 1. Live DFIR & Digital Forensics

#### `dfir_triage` — Live System Collector
Captures volatile host state, active sockets, deleted binaries running from memory, cron jobs, and user accounts.
```bash
# Quick triage to terminal (processes, open sockets, suspicious binaries)
python3 dfir_triage/dfir_triage.py quick

# Full comprehensive triage dump to JSON
python3 dfir_triage/dfir_triage.py full -o /tmp/triage.json

# Triage and package into an incident tarball
python3 dfir_triage/dfir_triage.py tar -o /tmp/host_triage.tar.gz
```

#### `ad1_parser` — AccessData FTK AD1 Image Parser
Fast streaming parser for logical FTK `.ad1` evidence images without mounting the volume.
```bash
# List all files and directories in the AD1 archive
python3 ad1_parser/ad1_parser.py list evidence.ad1

# Search for specific filenames or patterns
python3 ad1_parser/ad1_parser.py search evidence.ad1 --pattern ".*\.bash_history"

# Extract files matching a pattern
python3 ad1_parser/ad1_parser.py extract evidence.ad1 --pattern "shadow" -o ./extracted/
```

#### `artifact_hunter` — Forensic Artifact & Credential Sweeper
Recursively inspects directories or mounted images for credential stores, history files, and browser profiles.
```bash
# Search high-value file paths (SSH keys, AWS configs, bash history, .env)
python3 artifact_hunter/artifact_hunter.py paths /mnt/evidence

# Search file contents for leaked tokens, keys, and connection strings
python3 artifact_hunter/artifact_hunter.py creds /mnt/evidence -o creds_found.txt

# Locate files modified within the last 12 hours
python3 artifact_hunter/artifact_hunter.py recent /mnt/evidence --hours 12
```

#### `evidence_collector` — Evidence Hash & Chain of Custody
Collects target evidence files, hashes them with MD5 and SHA-256, and logs chain of custody metadata.
```bash
# Collect and hash a target directory or file
python3 evidence_collector/evidence_collector.py collect /var/log/nginx -o ./evidence_repo
```

#### `pcap_analyzer` — Pure-Python Packet Capture Inspector
Analyzes `.pcap` or `.pcapng` network dumps for conversations, cleartext passwords, and protocol statistics.
```bash
# Summarize traffic, talkers, and protocols
python3 pcap_analyzer/pcap_analyzer.py summary capture.pcap

# Extract DNS queries and HTTP requests
python3 pcap_analyzer/pcap_analyzer.py dns capture.pcap
python3 pcap_analyzer/pcap_analyzer.py http capture.pcap

# Carve cleartext credentials (FTP, Telnet, HTTP Basic)
python3 pcap_analyzer/pcap_analyzer.py creds capture.pcap
```

#### `stego_triage` — Steganography & File Analysis
Runs quick heuristics on suspect media and binary files to reveal hidden payloads.
```bash
# Full automated triage of an image or file
python3 stego_triage/stego_triage.py scan suspect.png

# Check magic bytes against file extension
python3 stego_triage/stego_triage.py magic suspect.png

# Detect trailing/appended data (appended ZIP/tar)
python3 stego_triage/stego_triage.py trailing suspect.png --extract
```

---

### 2. SIEM, Threat Detection & Log Analysis

#### `ioc_hunter` — Indicator of Compromise Extractor
High-throughput regex and heuristic engine extracting actionable IoCs from raw logs or memory dumps.
```bash
# Extract all IoCs (IPs, URLs, MD5/SHA256, CVEs, emails)
python3 ioc_hunter/ioc_extract.py /var/log/syslog -o iocs.json

# Filter specifically for IPv4 and domain indicators
python3 ioc_hunter/ioc_extract.py /var/log/nginx/access.log --types ip,domain
```

#### `log_analyzer` — Web & Auth Log Anomaly Detection
Identifies web application attacks, directory traversal, SQL injection, and authentication brute-force spikes.
```bash
# Analyze Nginx or Apache access logs
python3 log_analyzer/log_analyzer.py access /var/log/nginx/access.log

# Analyze authentication attempts and brute-force events
python3 log_analyzer/log_analyzer.py auth /var/log/auth.log
```

#### `log_timeline` — Multi-Log Chronological Aggregator
Normalizes timestamps across heterogeneous log formats (syslog, auth, nginx, auditd) into a single ordered timeline.
```bash
# Generate chronological event timeline
python3 log_timeline/log_timeline.py /var/log/ --output timeline.csv --format csv
```

#### `elastic_siem` & `splunk_siem` — Query Builders
Generate ready-to-paste KQL, EQL, and Splunk SPL queries targeting MITRE ATT&CK techniques.
```bash
# Generate Elastic query for brute-force detection
python3 elastic_siem/elastic_query_builder.py brute_force --user "admin"

# Generate Splunk SPL for webshell hunting
python3 splunk_siem/splunk_query_builder.py webshell --index "web"
```
*(Cheat sheets available in `elastic_siem/elastic_queries.md` and `splunk_siem/splunk_queries.md`)*.

---

### 3. Host Defense, Hardening & Persistence Hunting

#### `firewall_manager` — Rapid Host Firewall Controller
Locks down host firewalls during live compromise scenarios.
```bash
# Audit current firewall rules
sudo python3 firewall_manager/firewall_manager.py status

# Allow only essential ports (e.g. 22, 80, 443) and drop all other inbound traffic
sudo python3 firewall_manager/firewall_manager.py allow --ports 22,80,443 --default-drop

# Block a malicious IP immediately
sudo python3 firewall_manager/firewall_manager.py ban 198.51.100.23
```

#### `vuln_patcher` — Automated Vulnerability Auditor & Fixer
Audits and patches standard Linux privilege escalation avenues.
```bash
# Run vulnerability audit (SUID, cron, world-writable files, SSH config)
python3 vuln_patcher/vuln_patcher.py audit

# Apply all safe automatic fixes
sudo python3 vuln_patcher/vuln_patcher.py patch-all

# Apply specific patch
sudo python3 vuln_patcher/vuln_patcher.py patch weak_ssh_config
```

#### `web_config_auditor` — Web & DB Hardening & Webshell Scanner
Inspects configuration files (Nginx, PHP, MySQL, PostgreSQL, Roundcube, GitLab) and scans webroots for webshell signatures.
```bash
# Audit all installed web and database server configurations
python3 web_config_auditor/web_config_auditor.py audit

# Scan webroot for PHP/JSP webshells and reverse shells
python3 web_config_auditor/web_config_auditor.py webshell /var/www/html
```

#### `persistence_hunter` — Persistence Mechanism Auditor
Comprehensive scanner checking every standard Linux persistence hook.
```bash
# Run full persistence audit
python3 persistence_hunter/persistence_hunter.py audit

# Scan systemd timers and service overrides
python3 persistence_hunter/persistence_hunter.py systemd
```

---

### 4. Service Resilience & Restoration

#### `service_doctor` — Service Health Diagnostic & Triage
Performs immediate diagnostics on downed or flapping systemd services and validates open ports.
```bash
# Run health check across common CTF services
python3 service_doctor/service_doctor.py check

# Scan for open ports and failed systemd units
python3 service_doctor/service_doctor.py scan

# Diagnose and attempt auto-restart on a failed service
sudo python3 service_doctor/service_doctor.py fix nginx
```

#### `service_restoration` — Baseline Snapshot & Diffing
Snapshots directory trees and file hashes to identify attacker-modified or corrupted files.
```bash
# Create golden baseline snapshot
python3 service_restoration/baseline_diff.py snapshot -o baseline.json --dirs /etc,/var/www

# Diff current state against baseline after compromise
python3 service_restoration/baseline_diff.py diff baseline.json --dirs /etc,/var/www
```

#### `cod_fixer` — Code Doctor & Syntax Repair
Automatically fixes formatting, line endings, indentation, and BOM headers that break service scripts.
```bash
# Dry-run analysis of a broken script or config
python3 cod_fixer/code_doctor.py /etc/nginx/nginx.conf

# Apply safe formatting fixes (strip BOM, convert CRLF->LF, fix mixed tabs/spaces)
python3 cod_fixer/code_doctor.py /etc/nginx/nginx.conf --apply
```

---

### 5. CTF Operations, Scoring & Reporting

#### `submission_tracker` — State-Machine Submission Manager
Prevents rule violations, deduplicates IoCs, and enforces submission sequence constraints.
```bash
# Initialize competition session
python3 submission_tracker/submission_tracker.py init --team "BlueOps"

# Record submitted IoC
python3 submission_tracker/submission_tracker.py add-ioc --type ip --value "203.0.113.5" --technique "T1190"

# View submission status and limits
python3 submission_tracker/submission_tracker.py status
```

#### `score_calculator` — CTF Score Modeler
Simulates points based on SLA uptime percentage, valid IoCs, and report quality coefficients.
```bash
python3 score_calculator/score_calculator.py --sla 95.5 --iocs 18 --k1 0.6 --k2 0.3 --k3 0.1
```

#### `report_builder` — Incident Response Report Generator
Builds formatted Markdown/HTML competition and executive reports with timelines, evidence references, and IoC tables.
```bash
python3 report_builder/report_builder.py generate \
  --incident "INC-2026-001" \
  --iocs iocs.json \
  --timeline timeline.csv \
  --output final_report.md
```

---

### 6. Cryptography, Encodings & Flag Hunting

#### `flag_hunnter` — Flag Extractor & Entropy Scanner
```bash
# Recursively search files and databases for flags matching prefixes or regex
python3 flag_hunnter/flag_hunter.py /path/to/evidence --prefixes ctf,flag,HTB

# Block-level Shannon entropy scanner to locate encrypted/compressed payloads
python3 flag_hunnter/entropy_scan.py evidence.bin --rows 100
```

#### `hash_toolkit` — Hash Calculator & Identifier
```bash
# Identify hash algorithm
python3 hash_toolkit/hash_toolkit.py identify "5f4dcc3b5aa765d61d8327deb882cf99"

# Verify against wordlist
python3 hash_toolkit/hash_toolkit.py crack "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist /usr/share/wordlists/rockyou.txt
```

#### `encoding_decoder` — Multi-Layer Recursive Decoder
```bash
# Decode multi-encoded string (Base64 -> Hex -> URL)
python3 encoding_decoder/encoding_decoder.py auto "VTJobGJtZDFjR1JsWTNSeQ=="
```

#### `zip_extracter` — Encrypted ZIP & Known-Plaintext Helper
```bash
# Inspect encrypted ZIP archive entries
python3 zip_extracter/zipcrypto_helper.py list archive.zip

# Prepare known-plaintext attack for bkcrack
python3 zip_extracter/zipcrypto_helper.py suggest archive.zip -o ./work
```

#### `scan` — Host Discovery & Process Tree Visualizer
```bash
# Map local network subnet
python3 scan/net_map.py --range 192.168.1.0/24

# Visualize process hierarchy with listening ports
python3 scan/proc_tree.py --conns-only
```

---

## 🔒 Operational Safety & Disclaimer

> [!WARNING]
> These tools are intended exclusively for authorized CTF competitions, educational laboratories, defense audits, and authorized Incident Response operations. Unauthorized scanning, modifying, or testing of systems without explicit written consent is illegal. Always verify operational scope before executing firewall, patching, or network commands.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
