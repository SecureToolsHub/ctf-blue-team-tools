# ioc_hunter

A high-speed Indicator of Compromise (IoC) extraction engine engineered to parse unstructured logs, memory dumps, process strings, and triage files.

## Features

- **Extensive IoC Coverage**: Extracts IPv4, IPv6, FQDN domains, URLs, email addresses, MD5/SHA-1/SHA-256 hashes, and CVE identifiers.
- **Smart Filtering**: Filters out internal RFC 1918 IPs, loopbacks, common benign domains (e.g. `localhost`, `ubuntu.com`), and false positives.
- **Flexible Output**: Supports output formatted as plain text tables, line-delimited lists, or structured JSON.

## Usage

```bash
# Extract all IoCs from a log file or directory
python3 ioc_extract.py /var/log/nginx/access.log -o iocs.json

# Filter extraction to specific indicator types
python3 ioc_extract.py /var/log/syslog --types ip,domain,hash

# Pipe directly from stdin
cat /var/log/auth.log | python3 ioc_extract.py - --format json
```
