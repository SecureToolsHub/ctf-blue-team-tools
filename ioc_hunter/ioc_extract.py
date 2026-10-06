#!/usr/bin/env python3
"""
ioc_extract.py — Extract Indicators of Compromise from logs/text.

Types extracted: IPv4, IPv6, domains, URLs, email addresses,
MD5/SHA1/SHA256 hashes, CVE IDs.

Handles deliberately-obfuscated IOCs found in reports/logs
(hxxp://, 1[.]2[.]3[.]4, user[at]domain[.]com) by refanging them
before matching, and can defang its own output for safe reporting.

Usage:
    python3 ioc_extract.py access.log
    python3 ioc_extract.py ./logs_dir
    python3 ioc_extract.py ./logs_dir --types ip,domain,url
    python3 ioc_extract.py ./logs_dir --exclude-private
    python3 ioc_extract.py ./logs_dir --defang -o iocs.csv --format csv
    python3 ioc_extract.py ./logs_dir --format json -o iocs.json
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict

CHUNK_SIZE = 4 * 1024 * 1024
OVERLAP = 512

COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "ru", "cn", "uk", "de",
    "fr", "xyz", "top", "club", "online", "site", "tech", "uz", "su", "gov",
    "edu", "mil", "int", "me", "tv", "cc", "ws", "in", "us", "ca", "au",
    "jp", "kr", "br", "pl", "nl", "se", "no", "fi", "dk", "ch", "at", "be",
    "es", "it", "pt", "gr", "tr", "ir", "sa", "ae", "il", "pk", "bd", "vn",
    "th", "id", "my", "sg", "ph", "nz", "za", "ng", "ke", "eg", "ua", "by",
    "kz", "am", "az", "ge", "md", "lt", "lv", "ee", "app", "dev", "cloud",
    "shop", "store", "link", "live", "world", "icu", "email", "name",
}

PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"([a-zA-Z]{2,24})\b"
    ),
    "url": re.compile(
        r"\b(?:https?|ftp)://[^\s'\"<>\)\]]+", re.IGNORECASE
    ),
    "email": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "username": re.compile(r"\b(?:root|admin|sysadmin|ansible|postgres|mysql|oracle|tomcat|jenkins|docker|git|gitlab-runner|www-data|daemon|bin|sys|sync|games|man|lp|mail|news|uucp|proxy|backup|list|irc|gnats|nobody|systemd-network|syslog|messagebus|_apt|uuidd|tcpdump|sshd|landscape|pollinate|ubuntu|centos|ec2-user|vagrant|guest|test|pi)\b", re.IGNORECASE),
    "filename": re.compile(r"\b[\w.-]+\.(?:exe|sh|ps1|rar|zip)\b", re.IGNORECASE),
    "tool": re.compile(r"\b(?:chisel|linpeas|mimikatz|meterpreter|metasploit|cobalt strike|mythic|sliver|havoc|empire)\b", re.IGNORECASE),
}

INFOSTEALER_PATTERN = re.compile(r"(?i)(?:AppData[\\/]Local[\\/]Google[\\/]Chrome[\\/]User Data|Local Settings[\\/]Application Data|\.lnk|Recycle\.Bin|Login Data|Places\.sqlite|key3\.db|key4\.db|cert8\.db|cert9\.db)")
ROUNDCUBE_PATTERN = re.compile(r"(?i)(?:Subject:.*<\?php|GET /.*_task=mail|POST /.*_task=mail|PHP Parse error|PHP Fatal error)")

MITRE_MAPPING = {
    "ipv4": "T1110 (Brute Force) / T1190 (Exploit Public-Facing)",
    "ipv6": "T1110 (Brute Force) / T1190 (Exploit Public-Facing)",
    "domain": "T1071 (Application Layer Protocol)",
    "url": "T1071 (Application Layer Protocol)",
    "email": "T1534 (Internal Spearphishing) / T1566 (Phishing)",
    "md5": "T1588 (Obtain Capabilities)",
    "sha1": "T1588 (Obtain Capabilities)",
    "sha256": "T1588 (Obtain Capabilities)",
    "cve": "T1190 (Exploit Public-Facing)",
    "username": "T1110 (Brute Force)",
    "filename": "T1059 (Command and Scripting Interpreter)",
    "tool": "T1588 (Obtain Capabilities)",
    "infostealer_artifact": "T1005 (Data from Local System) / T1552 (Credentials in Files)",
    "roundcube_rce": "T1190 (Exploit Public-Facing)"
}


REFANG_RULES = [
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]|\(at\)|\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\s+dot\s+", re.IGNORECASE), "."),
]


def refang(text: str) -> str:
    for pattern, repl in REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(value: str, kind: str) -> str:
    v = value
    if kind in ("ipv4", "ipv6", "domain"):
        v = v.replace(".", "[.]")
    if kind == "url":
        v = re.sub(r"^https?", lambda m: "hxxp" + m.group(0)[4:], v, flags=re.IGNORECASE)
        v = v.replace(".", "[.]")
    if kind == "email":
        v = v.replace("@", "[at]").replace(".", "[.]")
    return v


def is_interesting_ip(ip_str, exclude_private):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not exclude_private:
        return True
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return False
    return True


def iter_files(path):
    if os.path.isfile(path):
        yield path
    else:
        for root, _, files in os.walk(path):
            if ".git" in root.split(os.sep):
                continue
            for name in files:
                yield os.path.join(root, name)


def extract_from_text(text, types, exclude_private):
    found = []
    for kind in types:
        if kind not in PATTERNS:
            continue
        pattern = PATTERNS[kind]
        for m in pattern.finditer(text):
            val = m.group(0)
            if kind == "domain":
                tld = m.group(1).lower()
                if tld not in COMMON_TLDS:
                    continue
                if val.replace(".", "").isdigit():
                    continue
            if kind == "ipv4" and not is_interesting_ip(val, exclude_private):
                continue
            if kind == "ipv6":
                if val.count(":") < 2:
                    continue
                if not is_interesting_ip(val, exclude_private):
                    continue
            found.append((kind, val))
    return found


def scan_file(path, types, exclude_private, no_refang, max_size, context_lines=0, infostealer_check=False, roundcube_check=False):
    results = []
    try:
        size = os.path.getsize(path)
    except OSError:
        return results
    if max_size and size > max_size:
        return results

    if context_lines > 0 or infostealer_check or roundcube_check:
        try:
            with open(path, "rb") as f:
                lines = f.readlines()
            for i, raw_line in enumerate(lines):
                text = raw_line.decode("utf-8", errors="ignore")
                if not no_refang:
                    text = refang(text)
                
                hits = extract_from_text(text, types, exclude_private)
                
                if infostealer_check:
                    for m in INFOSTEALER_PATTERN.finditer(text):
                        hits.append(("infostealer_artifact", m.group(0)))
                if roundcube_check:
                    for m in ROUNDCUBE_PATTERN.finditer(text):
                        hits.append(("roundcube_rce", m.group(0)))
                
                for kind, val in hits:
                    start = max(0, i - context_lines)
                    end = min(len(lines), i + context_lines + 1)
                    ctx = [l.decode("utf-8", errors="ignore").rstrip("\\n") for l in lines[start:end]]
                    results.append((kind, val, ctx))
            return results
        except (OSError, PermissionError):
            pass
        return results

    try:
        with open(path, "rb") as f:
            prev_tail = ""
            while True:
                raw = f.read(CHUNK_SIZE)
                if not raw:
                    break
                text = raw.decode("utf-8", errors="ignore")
                if not no_refang:
                    text = refang(text)
                window = prev_tail + text
                hits = extract_from_text(window, types, exclude_private)
                for kind, val in hits:
                    results.append((kind, val, None))
                prev_tail = window[-OVERLAP:] if len(window) > OVERLAP else window
    except (OSError, PermissionError):
        pass
    return results


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs from logs/text")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--types", default="ipv4,ipv6,domain,url,email,md5,sha1,sha256,cve,username,filename,tool",
                         help="Comma-separated IOC types to extract")
    parser.add_argument("--exclude-private", action="store_true",
                         help="Drop private/loopback/reserved/multicast IPs")
    parser.add_argument("--no-refang", action="store_true",
                         help="Don't un-obfuscate hxxp/[.]/[at] before matching")
    parser.add_argument("--defang", action="store_true",
                         help="Defang IOCs in the output (safe for reports)")
    parser.add_argument("--by-file", action="store_true",
                         help="Show which file(s) each IOC came from")
    parser.add_argument("--max-size", type=int, default=0,
                         help="Skip files larger than this many bytes (0 = no limit)")
    parser.add_argument("--format", choices=["text", "csv", "json"], default="text")
    parser.add_argument("-o", "--output", help="Write results to file")
    
    parser.add_argument("--context", type=int, default=0, help="Show N lines of surrounding context for each IOC hit")
    parser.add_argument("--mitre-map", action="store_true", help="Suggest likely MITRE ATT&CK technique based on IOC type/pattern")
    parser.add_argument("--known-iocs", help="Load a JSON file of known-bad IoCs and highlight matches in red")
    parser.add_argument("--infostealer-check", action="store_true", help="Scan for patterns associated with infostealers")
    parser.add_argument("--roundcube-check", action="store_true", help="Scan Roundcube logs specifically for RCE patterns")

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    types = [t.strip().lower() for t in args.types.split(",")]
    if args.infostealer_check and "infostealer_artifact" not in types:
        types.append("infostealer_artifact")
    if args.roundcube_check and "roundcube_rce" not in types:
        types.append("roundcube_rce")
        
    if not types:
        print("No valid IOC types selected.", file=sys.stderr)
        sys.exit(1)

    known_iocs = set()
    if args.known_iocs and os.path.exists(args.known_iocs):
        try:
            with open(args.known_iocs, "r") as f:
                data = json.load(f)
                for item in data:
                    if isinstance(item, dict) and "value" in item:
                        known_iocs.add(item["value"])
                    elif isinstance(item, str):
                        known_iocs.add(item)
        except Exception as e:
            print(f"Error loading known IOCs: {e}", file=sys.stderr)

    files = list(iter_files(args.path))
    print(f"[+] Scanning {len(files)} file(s) for: {', '.join(types)}", file=sys.stderr)

    counts = Counter()
    sources = defaultdict(set)
    contexts = defaultdict(list)

    for f in files:
        hits = scan_file(f, types, args.exclude_private, args.no_refang, args.max_size, args.context, args.infostealer_check, args.roundcube_check)
        for kind, val, ctx in hits:
            counts[(kind, val)] += 1
            sources[(kind, val)].add(f)
            if ctx:
                contexts[(kind, val)].append(ctx)

    grouped = defaultdict(list)
    for (kind, val), cnt in counts.items():
        grouped[kind].append((val, cnt))
    for kind in grouped:
        grouped[kind].sort(key=lambda x: -x[1])

    total = sum(counts.values())
    print(f"[+] {len(counts)} unique IOC(s), {total} total occurrence(s)\n", file=sys.stderr)

    rows = []
    for kind in types:
        for val, cnt in grouped.get(kind, []):
            display = defang(val, kind) if args.defang else val
            file_list = ";".join(os.path.relpath(p) for p in sources[(kind, val)]) if args.by_file else ""
            rows.append({"type": kind, "value": display, "count": cnt, "files": file_list})

    if args.format == "text":
        out_lines = []
        for kind in types:
            items = grouped.get(kind, [])
            if not items:
                continue
            out_lines.append(f"\n== {kind.upper()} ({len(items)}) ==")
            for val, cnt in items:
                display = defang(val, kind) if args.defang else val
                
                # Highlight if known IOC
                if args.known_iocs and val in known_iocs:
                    display = f"\033[91m{display}\033[0m"
                    
                line = f"  {display}   (x{cnt})"
                if args.by_file:
                    line += f"   [{';'.join(os.path.relpath(p) for p in sources[(kind, val)])}]"
                if args.mitre_map:
                    line += f"   [MITRE: {MITRE_MAPPING.get(kind, 'Unknown')}]"
                out_lines.append(line)
                
                if args.context and contexts.get((kind, val)):
                    for c_idx, ctx in enumerate(contexts[(kind, val)][:2]): # Limit to 2 contexts for brevity
                        out_lines.append(f"    --- Context {c_idx+1} ---")
                        for cline in ctx:
                            out_lines.append(f"    {cline}")
                        out_lines.append(f"    -----------------")
                        
        text_out = "\n".join(out_lines) if out_lines else "No IOCs found."
        print(text_out)
        if args.output:
            with open(args.output, "w") as f:
                f.write(text_out + "\n")

    elif args.format == "csv":
        target = open(args.output, "w", newline="") if args.output else sys.stdout
        writer = csv.DictWriter(target, fieldnames=["type", "value", "count", "files"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        if args.output:
            target.close()

    elif args.format == "json":
        text_out = json.dumps(rows, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(text_out)
        else:
            print(text_out)

    if args.output:
        print(f"\n[+] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
