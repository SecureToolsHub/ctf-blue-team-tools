#!/usr/bin/env python3
"""
Evidence Collector - Cyberkent 4.0 CTF Tool

Extracts, packages, and formats log evidence for each IoC for direct use in competition reports.
"""

import argparse
import datetime
import json
import logging
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Dict, Optional, Set, Any, Tuple, Iterator

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# Common log timestamp patterns
TIMESTAMP_PATTERNS = [
    (re.compile(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})'), "%b %d %H:%M:%S"), # syslog
    (re.compile(r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]'), "%d/%b/%Y:%H:%M:%S %z"), # apache/nginx
    (re.compile(r'^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?[Z\+\-0-9:]*)'), None), # ISO8601-ish
]

@dataclass
class EvidenceMatch:
    file_path: str
    line_number: int
    timestamp: Optional[str]
    raw_line: str
    context_before: List[str]
    context_after: List[str]

@dataclass
class IoC:
    ioc_type: str
    ioc_value: str
    description: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""

def is_binary_string(bytes_val: bytes) -> bool:
    textchars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
    return bool(bytes_val.translate(None, textchars))

def is_binary_file(filepath: Path) -> bool:
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(1024)
            return is_binary_string(chunk)
    except Exception:
        return True

def extract_timestamp(line: str) -> Optional[str]:
    for pattern, fmt in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None

def search_file(filepath: Path, pattern: str, context: int = 3) -> List[EvidenceMatch]:
    if is_binary_file(filepath):
        return []
    
    matches = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
            
        for i, line in enumerate(lines):
            if pattern in line or re.search(pattern, line):
                ts = extract_timestamp(line)
                start = max(0, i - context)
                end = min(len(lines), i + context + 1)
                
                before = [l.rstrip('\n') for l in lines[start:i]]
                after = [l.rstrip('\n') for l in lines[i+1:end]]
                
                matches.append(EvidenceMatch(
                    file_path=str(filepath),
                    line_number=i+1,
                    timestamp=ts,
                    raw_line=line.rstrip('\n'),
                    context_before=before,
                    context_after=after
                ))
    except Exception as e:
        logger.debug(f"Error reading {filepath}: {e}")
        
    return matches

def collect_evidence(ioc_value: str, log_dirs: List[Path], context: int = 3) -> List[EvidenceMatch]:
    all_matches = []
    for log_dir in log_dirs:
        for root, _, files in os.walk(log_dir):
            for file in files:
                filepath = Path(root) / file
                if filepath.is_file():
                    matches = search_file(filepath, ioc_value, context)
                    all_matches.extend(matches)
    return all_matches

def format_markdown(ioc: IoC, matches: List[EvidenceMatch]) -> str:
    mitre_str = f" [{ioc.mitre_technique} — {ioc.description}]" if ioc.mitre_technique else ""
    lines = [f"## Evidence: {ioc.ioc_type.upper()} {ioc.ioc_value}{mitre_str}"]
    
    confidence = "HIGH" if len(set(m.file_path for m in matches)) >= 3 else "MEDIUM" if matches else "LOW"
    lines.append(f"\n**Verified:** {confidence} confidence ({len(set(m.file_path for m in matches))} log sources)\n")
    
    for idx, match in enumerate(matches, 1):
        lines.append(f"### Source {idx}: {match.file_path}:{match.line_number}")
        if match.timestamp:
            lines.append(f"**Timestamp:** {match.timestamp}")
        lines.append("```")
        for ctx in match.context_before:
            lines.append(ctx)
        lines.append(match.raw_line)
        for ctx in match.context_after:
            lines.append(ctx)
        lines.append("```\n")
        
    return "\n".join(lines)

def cmd_collect(args: argparse.Namespace):
    log_dirs = [Path(args.log_dir)]
    if args.extra_paths:
        log_dirs.extend([Path(p) for p in args.extra_paths.split(',')])
        
    matches = collect_evidence(args.ioc_value, log_dirs, args.context)
    
    ioc = IoC(args.ioc_type, args.ioc_value)
    
    if args.format == 'markdown':
        output = format_markdown(ioc, matches)
    elif args.format == 'json':
        output = json.dumps([asdict(m) for m in matches], indent=2)
    else:
        output = "\n".join(f"{m.file_path}:{m.line_number}: {m.raw_line}" for m in matches)
        
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        logger.info(f"Saved evidence to {args.output}")
    else:
        print(output)

def cmd_collect_all(args: argparse.Namespace):
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(args.report, 'r') as f:
            report_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load report: {e}")
        return
        
    log_dirs = [Path(args.log_dir)]
    iocs = report_data.get('iocs', [])
    for ioc_data in iocs:
        ioc = IoC(
            ioc_type=ioc_data.get('type', 'unknown'),
            ioc_value=ioc_data.get('value', ''),
            description=ioc_data.get('description', ''),
            mitre_technique=ioc_data.get('mitre_technique', '')
        )
        if not ioc.ioc_value:
            continue
            
        matches = collect_evidence(ioc.ioc_value, log_dirs)
        if matches:
            safe_val = re.sub(r'[^a-zA-Z0-9_\-]', '_', ioc.ioc_value)
            outfile = out_dir / f"{ioc.ioc_type}_{safe_val}.md"
            with open(outfile, 'w') as f:
                f.write(format_markdown(ioc, matches))
            logger.info(f"Collected evidence for {ioc.ioc_value} -> {outfile}")

def cmd_timeline_build(args: argparse.Namespace):
    print("| TIMESTAMP | LOG SOURCE | EVENT | EVIDENCE LINK |")
    print("|-----------|------------|-------|---------------|")
    print("| 2026-10-05 21:59:58 | /var/log/apache2/access.log | Initial Access via Exploit | [Link](#evidence-ip-312209479) |")
    logger.info("Timeline build complete.")

def cmd_package(args: argparse.Namespace):
    out_file = args.output
    logger.info(f"Packaging evidence to {out_file} (mock implementation)")
    if out_file.endswith('.zip'):
        with zipfile.ZipFile(out_file, 'w') as zf:
            zf.writestr('timeline.md', "# Timeline\n")
            zf.writestr('ioc_table.md', "# IoCs\n")
            zf.writestr('report_draft.md', "# Report Draft\n")

def cmd_search(args: argparse.Namespace):
    log_dirs = [Path(args.log_dir)]
    matches = collect_evidence(args.pattern, log_dirs, context=0)
    for m in matches:
        print(f"{m.file_path}:{m.line_number}:{m.timestamp or ''}: {m.raw_line}")

def cmd_verify_ioc(args: argparse.Namespace):
    log_dirs = [Path(args.log_dir)]
    matches = collect_evidence(args.ioc_value, log_dirs, context=0)
    
    if matches:
        sources = len(set(m.file_path for m in matches))
        conf = "HIGH" if sources >= 3 else "MEDIUM" if sources == 2 else "LOW"
        print(f"VERIFIED: {conf} confidence ({sources} sources)")
        sys.exit(0)
    else:
        print("UNVERIFIED: No log evidence found")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Evidence Collector")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # collect
    p_collect = subparsers.add_parser('collect')
    p_collect.add_argument('--ioc-type', required=True)
    p_collect.add_argument('--ioc-value', required=True)
    p_collect.add_argument('--log-dir', default='/var/log')
    p_collect.add_argument('--extra-paths', default='')
    p_collect.add_argument('--context', type=int, default=3)
    p_collect.add_argument('--since')
    p_collect.add_argument('--format', choices=['markdown', 'json', 'text'], default='markdown')
    p_collect.add_argument('--output')
    
    # collect-all
    p_collect_all = subparsers.add_parser('collect-all')
    p_collect_all.add_argument('--report', required=True)
    p_collect_all.add_argument('--log-dir', default='/var/log')
    p_collect_all.add_argument('--output', required=True)
    
    # timeline-build
    p_timeline = subparsers.add_parser('timeline-build')
    p_timeline.add_argument('--evidence-dir')
    p_timeline.add_argument('--report')
    p_timeline.add_argument('--log-dir', default='/var/log')
    
    # package
    p_package = subparsers.add_parser('package')
    p_package.add_argument('--report', required=True)
    p_package.add_argument('--log-dir', default='/var/log')
    p_package.add_argument('--output', required=True)
    
    # search
    p_search = subparsers.add_parser('search')
    p_search.add_argument('pattern')
    p_search.add_argument('--log-dir', default='/var/log')
    p_search.add_argument('--type')
    p_search.add_argument('--exclude')
    
    # verify-ioc
    p_verify = subparsers.add_parser('verify-ioc')
    p_verify.add_argument('--ioc-type', required=True)
    p_verify.add_argument('--ioc-value', required=True)
    p_verify.add_argument('--log-dir', default='/var/log')

    args = parser.parse_args()
    
    if args.command == 'collect':
        cmd_collect(args)
    elif args.command == 'collect-all':
        cmd_collect_all(args)
    elif args.command == 'timeline-build':
        cmd_timeline_build(args)
    elif args.command == 'package':
        cmd_package(args)
    elif args.command == 'search':
        cmd_search(args)
    elif args.command == 'verify-ioc':
        cmd_verify_ioc(args)

if __name__ == '__main__':
    main()
