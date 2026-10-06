# log_analyzer

A lightweight, high-performance log inspection and anomaly detection utility for web servers and system authentication logs.

## Features

- **Web Server Analysis (`access`)**: Parses Nginx and Apache Combined/Common access logs; detects SQL injection, cross-site scripting (XSS), path traversal, scanning tools, HTTP error rate spikes, and top source IPs.
- **Authentication Analysis (`auth`)**: Parses Linux `/var/log/auth.log` or `secure`; detects SSH brute-force attempts, invalid user enumerations, and successful privilege escalation events.
- **Reporting**: Generates tabular terminal summaries and optional JSON reports for ingestion into SIEM or IR pipelines.

## Usage

```bash
# Analyze web access logs for attacks and anomalous traffic
python3 log_analyzer.py access /var/log/nginx/access.log

# Analyze authentication logs for brute-force attacks
python3 log_analyzer.py auth /var/log/auth.log

# Export structured findings to JSON
python3 log_analyzer.py access /var/log/nginx/access.log --json -o web_findings.json
```
