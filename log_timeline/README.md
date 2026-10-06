# log_timeline

A multi-source log aggregation and chronological normalization tool for digital forensics and incident response timeline reconstruction.

## Features

- **Multi-Format Ingestion**: Ingests disparate log sources simultaneously (syslog, auth.log, Nginx/Apache access logs, auditd, custom application logs).
- **Timestamp Normalization**: Parses and unifies heterogeneous date/time formats into standardized ISO 8601 UTC timestamps.
- **Search & Filtering**: Filter events by keyword regex, IP address, user account, or bounded time ranges.
- **Structured Export**: Outputs consolidated chronological timelines into CSV, JSON, or clean Markdown tables.

## Usage

```bash
# Aggregate all logs in a directory into a chronological timeline
python3 log_timeline.py /var/log/ --output timeline.csv --format csv

# Filter timeline by time window and keyword
python3 log_timeline.py /var/log/ --since "2026-10-05T00:00:00" --until "2026-10-06T00:00:00" --contains "root"

# Export timeline to Markdown format for incident reports
python3 log_timeline.py /var/log/auth.log /var/log/nginx/access.log --format markdown -o timeline.md
```
