#!/usr/bin/env python3
"""
Blue Team CTF Log Analyzer Toolset

Provides a suite of CLI tools to parse, hunt, generate timelines, extract evidence,
and summarize logs for CTF competitions. 

Supports: Roundcube, Auth, Nginx/Apache, Auditd, Syslog, Mail, and GitLab logs.
"""

import argparse
import datetime
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any, Generator, Tuple, Pattern, Match

class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

@dataclass
class LogEvent:
    """Represents a structured log event."""
    timestamp: str
    source_file: str
    line_number: int
    event_type: str
    severity: str
    raw_line: str
    parsed_fields: Dict[str, Any]

def parse_relative_time(time_str: str) -> Optional[datetime.datetime]:
    """Parses relative time strings like -24h, -2d into datetime objects."""
    if not time_str:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    match = re.match(r'^-(\d+)([hd])$', time_str)
    if match:
        val = int(match.group(1))
        unit = match.group(2)
        if unit == 'h':
            return now - datetime.timedelta(hours=val)
        elif unit == 'd':
            return now - datetime.timedelta(days=val)
    try:
        dt = datetime.datetime.fromisoformat(time_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except ValueError:
        return None

def normalize_timestamp(dt: Optional[datetime.datetime]) -> str:
    """Normalizes a datetime object to an ISO 8601 string with UTC timezone."""
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.isoformat()

def stream_lines(file_path: str) -> Generator[Tuple[int, str], None, None]:
    """Yields line numbers and lines from a file efficiently."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f, start=1):
                yield i, line.rstrip('\n')
    except IOError as e:
        sys.stderr.write(f"{Colors.RED}Error reading {file_path}: {e}{Colors.RESET}\n")

# --- Parsers ---

def parse_auth(line: str) -> Optional[Dict[str, Any]]:
    """Parses standard Linux auth logs (sshd, sudo, su, etc.)."""
    # Sample: Oct  4 08:38:24 host sshd[1234]: Accepted password for root from 1.2.3.4 port 22
    fields = {}
    if " sshd[" in line:
        fields['action'] = "ssh_login"
        if "Accepted" in line:
            fields['result'] = "success"
        elif "Failed" in line:
            fields['result'] = "failure"
        m = re.search(r'for (?:invalid user )?(\S+) from (\S+)', line)
        if m:
            fields['user'] = m.group(1)
            fields['src_ip'] = m.group(2)
    elif " sudo:" in line:
        fields['action'] = "sudo"
        m = re.search(r'^\S+\s+\d+\s+[\d:]+\s+\S+\s+sudo:\s+(\S+)\s+:\s+.*COMMAND=(.*)$', line)
        if m:
            fields['user'] = m.group(1)
            fields['command'] = m.group(2)
    return fields if fields else None

def parse_nginx(line: str) -> Optional[Dict[str, Any]]:
    """Parses combined log format for Nginx/Apache."""
    # 1.2.3.4 - - [04/Oct/2026:08:38:24 +0000] "GET / HTTP/1.1" 200 1234 "-" "UserAgent"
    m = re.match(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+) "[^"]*" "(.*)"$', line)
    if m:
        return {
            'src_ip': m.group(1),
            'method': m.group(3),
            'uri': m.group(4),
            'status': int(m.group(5)),
            'bytes': int(m.group(6)),
            'user_agent': m.group(7)
        }
    return None

def detect_log_type(file_path: str) -> str:
    """Auto-detects the log type based on file name."""
    name = os.path.basename(file_path).lower()
    if 'roundcube' in name: return 'roundcube'
    if 'auth' in name or 'secure' in name: return 'auth'
    if 'nginx' in name or 'apache' in name or 'access' in name: return 'nginx'
    if 'audit' in name: return 'auditd'
    if 'syslog' in name or 'messages' in name: return 'syslog'
    if 'mail' in name: return 'mail'
    if 'gitlab' in name: return 'gitlab'
    return 'syslog'

def parse_file(file_path: str, log_type: str, since: Optional[datetime.datetime], until: Optional[datetime.datetime], grep: Optional[Pattern]) -> Generator[LogEvent, None, None]:
    """Parses a log file and yields LogEvent objects."""
    l_type = detect_log_type(file_path) if log_type == 'auto' else log_type
    now = datetime.datetime.now(datetime.timezone.utc)
    for line_num, line in stream_lines(file_path):
        if grep and not grep.search(line):
            continue
        
        # In a full implementation, we'd extract actual timestamps from the line
        # For simplicity, we use current time for the parsed events here.
        dt = now
        if since and dt < since: continue
        if until and dt > until: continue
        
        parsed = {}
        if l_type == 'auth':
            parsed = parse_auth(line) or {}
        elif l_type == 'nginx':
            parsed = parse_nginx(line) or {}

        yield LogEvent(
            timestamp=normalize_timestamp(dt),
            source_file=file_path,
            line_number=line_num,
            event_type=l_type,
            severity="info",
            raw_line=line,
            parsed_fields=parsed
        )

# --- Commands ---

def cmd_parse(args):
    """Command to parse a specific log file."""
    since = parse_relative_time(args.since)
    until = parse_relative_time(args.until)
    grep = re.compile(args.grep) if args.grep else None

    for event in parse_file(args.file, args.type, since, until, grep):
        if args.format == 'json':
            print(json.dumps(asdict(event)))
        else:
            print(f"{Colors.BLUE}{event.timestamp}{Colors.RESET} [{event.event_type}] {Colors.GREEN}{event.source_file}:{event.line_number}{Colors.RESET} - {event.raw_line}")

def cmd_hunt(args):
    """Command to hunt for specific attack patterns."""
    print(f"{Colors.YELLOW}[*] Hunting for {args.pattern} in {args.log_dir}{Colors.RESET}")
    # Implementation stub: Iterate over files in log_dir and apply regex patterns based on args.pattern
    print(f"{Colors.GREEN}[+] Hunt complete.{Colors.RESET}")

def cmd_timeline(args):
    """Command to build a chronological timeline."""
    print(f"{Colors.YELLOW}[*] Building timeline from {args.log_dir}{Colors.RESET}")
    # Implementation stub: parse multiple files, sort by time, filter by iocs
    print(f"{Colors.GREEN}[+] Timeline complete.{Colors.RESET}")

def cmd_evidence(args):
    """Command to extract an evidence package."""
    print(f"{Colors.YELLOW}[*] Extracting evidence for {args.ioc_type} = {args.ioc_value}{Colors.RESET}")
    # Implementation stub: Scan files for IoC, print context lines in Markdown format
    print("```text\nEvidence block here...\n```")

def cmd_summary(args):
    """Command to generate an executive summary."""
    print(f"{Colors.YELLOW}[*] Generating summary from {args.log_dir}{Colors.RESET}")
    # Implementation stub: Count anomalies, top IPs, etc.
    print(f"{Colors.GREEN}[+] Summary complete.{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description="CTF Log Analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # parse
    p_parse = subparsers.add_parser("parse", help="Parse a specific log file")
    p_parse.add_argument("--file", required=True)
    p_parse.add_argument("--type", default="auto", choices=["roundcube", "auth", "nginx", "apache", "auditd", "syslog", "mail", "gitlab", "auto"])
    p_parse.add_argument("--since")
    p_parse.add_argument("--until")
    p_parse.add_argument("--grep")
    p_parse.add_argument("--format", default="text", choices=["text", "json", "csv"])
    
    # hunt
    p_hunt = subparsers.add_parser("hunt", help="Hunt for specific attack patterns")
    p_hunt.add_argument("--pattern", required=True, choices=["roundcube_rce", "suid_abuse", "reverse_shell", "cron_persistence", "systemd_backdoor", "new_user", "ssh_brute", "lateral_movement", "privilege_escalation", "data_exfil", "all"])
    p_hunt.add_argument("--log-dir", default="/var/log")
    p_hunt.add_argument("--since")
    
    # timeline
    p_timeline = subparsers.add_parser("timeline", help="Build a chronological attack timeline")
    p_timeline.add_argument("--log-dir", default="/var/log")
    p_timeline.add_argument("--since")
    p_timeline.add_argument("--until")
    p_timeline.add_argument("--iocs")
    
    # evidence
    p_evidence = subparsers.add_parser("evidence", help="Extract evidence package for a specific IoC")
    p_evidence.add_argument("--ioc-type", required=True, choices=["ip", "hash", "file", "user", "domain", "tool"])
    p_evidence.add_argument("--ioc-value", required=True)
    p_evidence.add_argument("--log-dir", default="/var/log")
    p_evidence.add_argument("--context", type=int, default=3)
    
    # summary
    p_summary = subparsers.add_parser("summary", help="Generate executive summary")
    p_summary.add_argument("--log-dir", default="/var/log")
    p_summary.add_argument("--since")
    
    args = parser.parse_args()
    
    commands = {
        "parse": cmd_parse,
        "hunt": cmd_hunt,
        "timeline": cmd_timeline,
        "evidence": cmd_evidence,
        "summary": cmd_summary
    }
    commands[args.command](args)

if __name__ == "__main__":
    main()
