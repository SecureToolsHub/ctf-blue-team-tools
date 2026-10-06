#!/usr/bin/env python3
"""
log_timeline.py — Merge multiple log formats into one unified,
sortable chronological timeline.

Supported formats (auto-detected per file):
  - syslog / auth.log        "Jan 15 10:00:01 host sshd[1234]: message"
  - Apache/Nginx combined    '1.2.3.4 - - [15/Jan/2026:10:00:01 +0000] "GET / HTTP/1.1" 200 512'
  - Generic ISO8601          "2026-01-15T10:00:01Z message" or "2026-01-15 10:00:01 message"
  - Windows Event Log CSV    (exported via PowerShell Get-WinEvent | Export-Csv)

Usage:
    python3 log_timeline.py ./logs
    python3 log_timeline.py auth.log access.log --start "2026-01-15 09:00" --end "2026-01-15 12:00"
    python3 log_timeline.py ./logs --contains "failed password"
    python3 log_timeline.py ./logs --host webserver01
    python3 log_timeline.py ./logs --format csv -o timeline.csv
"""

import argparse
import csv
import io
import os
import re
import sys
from datetime import datetime

# ---------------------------------------------------------------- parsers

SYSLOG_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s*[+-]\d{4})\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*[:\-]?\s*(?P<msg>.*)$"
)

CSV_TIME_COLUMNS = ["TimeCreated", "Timestamp", "Time", "Date", "EventTime", "DateTime"]
CSV_MSG_COLUMNS = ["Message", "Description", "Msg"]


def parse_syslog_line(line, default_year):
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(f"{default_year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None
    proc = m.group("proc")
    pid = m.group("pid")
    proc_disp = f"{proc}[{pid}]" if pid else proc
    return {
        "timestamp": ts, "log_type": "syslog", "host": m.group("host"),
        "message": f"{proc_disp}: {m.group('msg')}",
    }


def parse_apache_line(line):
    m = APACHE_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts").replace(" ", ""), "%d/%b/%Y:%H:%M:%S%z")
        ts = ts.replace(tzinfo=None)  # normalize to naive for cross-source sorting
    except ValueError:
        return None
    msg = f'{m.group("method")} {m.group("path")} -> {m.group("status")} ({m.group("size")} bytes)'
    return {
        "timestamp": ts, "log_type": "http", "host": m.group("ip"),
        "message": msg,
    }


def parse_iso_line(line):
    m = ISO_RE.match(line)
    if not m:
        return None
    raw = m.group("ts").replace("Z", "+00:00")
    try:
        ts = datetime.fromisoformat(raw)
        ts = ts.replace(tzinfo=None)
    except ValueError:
        return None
    return {
        "timestamp": ts, "log_type": "iso", "host": "",
        "message": m.group("msg"),
    }


def parse_line(line, default_year):
    line = line.rstrip("\n\r")
    if not line.strip():
        return None
    for parser in (parse_syslog_line, parse_apache_line, parse_iso_line):
        if parser is parse_syslog_line:
            result = parser(line, default_year)
        else:
            result = parser(line)
        if result:
            return result
    return None


def try_parse_timestamp_cell(value):
    fmts = [
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
    ]
    for fmt in fmts:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.strip().replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def parse_csv_file(path):
    events = []
    skipped = 0
    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                return events, 0
            ts_col = next((c for c in CSV_TIME_COLUMNS if c in reader.fieldnames), None)
            msg_col = next((c for c in CSV_MSG_COLUMNS if c in reader.fieldnames), None)
            if not ts_col:
                return events, 0
            for row in reader:
                ts = try_parse_timestamp_cell(row.get(ts_col, ""))
                if not ts:
                    skipped += 1
                    continue
                if msg_col and row.get(msg_col):
                    msg = row[msg_col]
                else:
                    msg = "; ".join(f"{k}={v}" for k, v in row.items()
                                     if k != ts_col and v)
                host = row.get("Host") or row.get("MachineName") or row.get("Computer") or ""
                events.append({
                    "timestamp": ts, "log_type": "winevt", "host": host,
                    "message": msg[:300],
                })
    except (OSError, csv.Error):
        return events, 0
    return events, skipped


def scan_file(path, default_year):
    events = []
    skipped = 0
    ext = os.path.splitext(path)[1].lower()

    if ext == ".csv":
        events, skipped = parse_csv_file(path)
        for e in events:
            e["source"] = path
        return events, skipped, len(events) + skipped

    total = 0
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                total += 1
                result = parse_line(line, default_year)
                if result:
                    result["source"] = path
                    events.append(result)
                else:
                    skipped += 1
    except (OSError, PermissionError):
        pass
    return events, skipped, total


def iter_input_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        elif os.path.isdir(p):
            for root, _, files in os.walk(p):
                if ".git" in root.split(os.sep):
                    continue
                for name in files:
                    yield os.path.join(root, name)


def main():
    parser = argparse.ArgumentParser(description="Merge multiple log formats into one timeline")
    parser.add_argument("paths", nargs="+", help="Log file(s) or directory/directories")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                         help="Year to assume for syslog lines (no year in format), default: current year")
    parser.add_argument("--start", help="Only show events at/after this time (e.g. '2026-01-15 09:00')")
    parser.add_argument("--end", help="Only show events at/before this time")
    parser.add_argument("--host", help="Filter to events matching this host/IP substring")
    parser.add_argument("--contains", help="Filter to events whose message matches this regex/keyword")
    parser.add_argument("--type", help="Filter to a log_type: syslog, http, iso, winevt")
    parser.add_argument("--format", choices=["text", "csv", "json"], default="text")
    parser.add_argument("-o", "--output", help="Write result to file")
    args = parser.parse_args()

    files = list(iter_input_files(args.paths))
    if not files:
        print("No input files found.", file=sys.stderr)
        sys.exit(1)

    all_events = []
    total_lines = 0
    total_skipped = 0
    for f in files:
        events, skipped, total = scan_file(f, args.year)
        all_events.extend(events)
        total_lines += total
        total_skipped += skipped

    start_dt = try_parse_timestamp_cell(args.start) if args.start else None
    end_dt = try_parse_timestamp_cell(args.end) if args.end else None
    contains_re = re.compile(args.contains, re.IGNORECASE) if args.contains else None

    filtered = []
    for e in all_events:
        if start_dt and e["timestamp"] < start_dt:
            continue
        if end_dt and e["timestamp"] > end_dt:
            continue
        if args.host and args.host.lower() not in e["host"].lower():
            continue
        if args.type and e["log_type"] != args.type:
            continue
        if contains_re and not contains_re.search(e["message"]):
            continue
        filtered.append(e)

    filtered.sort(key=lambda e: e["timestamp"])

    print(f"[+] Parsed {len(all_events)}/{total_lines} lines across {len(files)} file(s) "
          f"({total_skipped} unparsed)", file=sys.stderr)
    print(f"[+] {len(filtered)} event(s) after filters\n", file=sys.stderr)

    if args.format == "text":
        lines = []
        for e in filtered:
            ts = e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
            host = e["host"] or "-"
            lines.append(f"{ts}  [{e['log_type']:<7}] {host:<20} {e['message']}")
        text_out = "\n".join(lines) if lines else "No events matched."
        print(text_out)
        if args.output:
            with open(args.output, "w") as f:
                f.write(text_out + "\n")

    elif args.format == "csv":
        target = open(args.output, "w", newline="") if args.output else sys.stdout
        writer = csv.DictWriter(target, fieldnames=["timestamp", "log_type", "host", "message", "source"])
        writer.writeheader()
        for e in filtered:
            writer.writerow({
                "timestamp": e["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                "log_type": e["log_type"], "host": e["host"],
                "message": e["message"], "source": e["source"],
            })
        if args.output:
            target.close()

    elif args.format == "json":
        import json
        out = [{
            "timestamp": e["timestamp"].strftime("%Y-%m-%dT%H:%M:%S"),
            "log_type": e["log_type"], "host": e["host"],
            "message": e["message"], "source": e["source"],
        } for e in filtered]
        text_out = json.dumps(out, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(text_out)
        else:
            print(text_out)

    if args.output:
        print(f"[+] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
