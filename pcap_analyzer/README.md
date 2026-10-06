# pcap_analyzer

A lightweight, standalone network packet capture (`.pcap` and `.pcapng`) analyzer implemented in pure Python without external dependencies (no Wireshark or Scapy required).

## Features

- **Traffic Profiling (`summary`)**: Computes bandwidth, top talkers, IP conversation matrices, and protocol distribution.
- **DNS Enumeration (`dns`)**: Extracts all DNS queries, answers, resolved IPs, and identifies potential DGA or tunneling domains.
- **HTTP Session Analysis (`http`)**: Inspects HTTP requests/responses, requested URIs, user agents, status codes, and methods.
- **Cleartext Credential Carving (`creds`)**: Carves unencrypted credentials from protocols such as Telnet, FTP, HTTP Basic Auth, and SMTP.
- **Suspicious Port Alerts**: Flags connections over unconventional or commonly exploited TCP/UDP ports.

## Usage

```bash
# General traffic summary and conversation matrix
python3 pcap_analyzer.py summary capture.pcap

# Inspect DNS queries and lookups
python3 pcap_analyzer.py dns capture.pcap

# Extract HTTP requests and web activity
python3 pcap_analyzer.py http capture.pcap

# Search for cleartext credentials and passwords
python3 pcap_analyzer.py creds capture.pcap
```
