#!/usr/bin/env python3
"""
artifact_hunter.py — Sweep a directory/mounted image for high-value
forensic artifacts: shell history, SSH keys, browser data, cloud
credentials, WSL rootfs paths, email files, and credential-looking
strings inside text/config files. Also surfaces recently modified
files, useful for spotting attacker-dropped/edited content.

Subcommands:
  paths     Walk the tree and flag filenames/paths matching known
            high-value artifact patterns.
  creds     Scan text/config file CONTENT for credential-looking
            strings (AWS keys, private keys, tokens, passwords, ...).
  recent    List files modified within a time window, newest first.
  all       Run all three and print a consolidated report.

Usage:
    python3 artifact_hunter.py paths ./evidence
    python3 artifact_hunter.py creds ./evidence --show-full
    python3 artifact_hunter.py recent ./evidence --since 24h
    python3 artifact_hunter.py all ./evidence -o report.txt
"""

import argparse
import os
import re
import sys
import time

# ---------------------------------------------------------------- paths

ARTIFACT_PATTERNS = [
    ("shell_history", r"\.bash_history$", "Bash command history"),
    ("shell_history", r"\.zsh_history$", "Zsh command history"),
    ("shell_history", r"\.python_history$", "Python REPL history"),
    ("shell_history", r"\.mysql_history$", "MySQL client history"),
    ("shell_history", r"\.psql_history$", "PostgreSQL client history"),
    ("shell_history", r"ConsoleHost_history\.txt$", "PowerShell history"),
    ("shell_history", r"\.node_repl_history$", "Node REPL history"),

    ("ssh", r"\.ssh/id_rsa$", "SSH private key (RSA)"),
    ("ssh", r"\.ssh/id_ed25519$", "SSH private key (ed25519)"),
    ("ssh", r"\.ssh/id_ecdsa$", "SSH private key (ECDSA)"),
    ("ssh", r"\.ssh/authorized_keys$", "SSH authorized_keys"),
    ("ssh", r"\.ssh/known_hosts$", "SSH known_hosts (lateral movement clues)"),
    ("ssh", r"\.ssh/config$", "SSH client config"),

    ("cloud_creds", r"\.aws/credentials$", "AWS credentials file"),
    ("cloud_creds", r"\.aws/config$", "AWS config file"),
    ("cloud_creds", r"\.azure/(accessTokens|credentials)", "Azure CLI credentials"),
    ("cloud_creds", r"\.config/gcloud/", "GCloud CLI credentials"),
    ("cloud_creds", r"\.docker/config\.json$", "Docker registry auth"),
    ("cloud_creds", r"\.kube/config$", "Kubernetes cluster credentials"),
    ("cloud_creds", r"\.netrc$", "netrc stored credentials"),
    ("cloud_creds", r"\.git-credentials$", "Git stored credentials"),

    ("browser", r"(Chrome|Edge|Brave)/.*/Login Data$", "Saved browser passwords (Chromium)"),
    ("browser", r"(Chrome|Edge|Brave)/.*/Cookies$", "Browser cookies (Chromium)"),
    ("browser", r"(Chrome|Edge|Brave)/.*/History$", "Browser history (Chromium)"),
    ("browser", r"(Chrome|Edge|Brave)/.*/Web Data$", "Browser autofill/form data"),
    ("browser", r"places\.sqlite$", "Firefox history/bookmarks"),
    ("browser", r"logins\.json$", "Firefox saved logins"),
    ("browser", r"key4\.db$", "Firefox credential encryption key store"),
    ("browser", r"cookies\.sqlite$", "Firefox cookies"),

    ("wsl", r"AppData/Local/Packages/.*Ubuntu.*/LocalState/rootfs", "WSL Ubuntu rootfs"),
    ("wsl", r"AppData/Local/Packages/.*Linux.*/LocalState/rootfs", "WSL Linux distro rootfs"),
    ("wsl", r"AppData/Local/lxss/", "WSL1 legacy rootfs"),

    ("email", r"\.pst$", "Outlook mailbox archive"),
    ("email", r"\.ost$", "Outlook offline mailbox"),
    ("email", r"\.eml$", "Individual email message"),
    ("email", r"\.msg$", "Outlook message file"),
    ("email", r"Mail/.*/cur/", "Maildir stored mail"),

    ("config_secret", r"\.env$", "Environment/secrets file"),
    ("config_secret", r"wp-config\.php$", "WordPress DB credentials"),
    ("config_secret", r"config\.php$", "Generic PHP config"),
    ("config_secret", r"web\.config$", "IIS/.NET web config"),
    ("config_secret", r"appsettings\.json$", ".NET app settings"),
    ("config_secret", r"settings\.py$", "Django settings (check SECRET_KEY)"),
    ("config_secret", r"\.npmrc$", "npm registry auth token"),
    ("config_secret", r"\.pypirc$", "PyPI upload credentials"),

    ("scheduled", r"crontab$", "Cron job definitions"),
    ("scheduled", r"/etc/cron\.", "System cron directory"),
    ("scheduled", r"Tasks/.*\.job$", "Windows scheduled task"),

    ("logs", r"/var/log/auth\.log", "Linux auth log (logins, sudo)"),
    ("logs", r"/var/log/secure$", "RHEL/CentOS auth log"),
    ("logs", r"Security\.evtx$", "Windows Security event log"),
    ("logs", r"System\.evtx$", "Windows System event log"),
    ("logs", r"\.pcap$", "Packet capture"),
    ("logs", r"\.pcapng$", "Packet capture (pcapng)"),
]

COMPILED_PATTERNS = [(cat, re.compile(pat, re.IGNORECASE), desc)
                      for cat, pat, desc in ARTIFACT_PATTERNS]


def scan_paths(root):
    hits = []
    for dirpath, _, filenames in os.walk(root):
        norm_dir = dirpath.replace(os.sep, "/")
        for name in filenames:
            full = os.path.join(dirpath, name).replace(os.sep, "/")
            for cat, pattern, desc in COMPILED_PATTERNS:
                if pattern.search(full):
                    try:
                        size = os.path.getsize(os.path.join(dirpath, name))
                    except OSError:
                        size = -1
                    hits.append({"category": cat, "path": full, "desc": desc, "size": size})
                    break
    return hits


# ------------------------------------------------------------- creds

CRED_PATTERNS = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,48}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("db_conn_string", re.compile(r"(?i)(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|jdbc:[a-z]+)://[^\s\"']+")),
    ("generic_password", re.compile(r"(?i)(?:password|passwd|pwd)\b\s*[:=]\s*['\"]?([^\s'\";,]{4,64})")),
    ("generic_secret", re.compile(r"(?i)\b(?:secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token)\b"
                                   r"\s*[:=]\s*['\"]?([A-Za-z0-9\-_./+=]{8,80})")),
]

SKIP_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".mp3", ".mp4",
                    ".avi", ".mov", ".zip", ".7z", ".rar", ".gz", ".exe", ".dll",
                    ".so", ".pdf", ".sqlite", ".db"}

CHUNK_SIZE = 4 * 1024 * 1024
OVERLAP = 256


def redact(value, show_full):
    if show_full or len(value) <= 8:
        return value
    return f"{value[:4]}...{value[-4:]} (len={len(value)})"


def scan_creds_file(path, max_size, show_full):
    hits = []
    ext = os.path.splitext(path)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return hits
    try:
        size = os.path.getsize(path)
    except OSError:
        return hits
    if max_size and size > max_size:
        return hits

    try:
        with open(path, "rb") as f:
            prev_tail = ""
            while True:
                raw = f.read(CHUNK_SIZE)
                if not raw:
                    break
                text = raw.decode("utf-8", errors="ignore")
                window = prev_tail + text
                for name, pattern in CRED_PATTERNS:
                    for m in pattern.finditer(window):
                        val = m.group(1) if m.groups() else m.group(0)
                        hits.append({"type": name, "value": redact(val, show_full), "path": path})
                prev_tail = window[-OVERLAP:] if len(window) > OVERLAP else window
    except (OSError, PermissionError):
        pass
    return hits


def scan_creds(root, max_size, show_full):
    all_hits = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            all_hits.extend(scan_creds_file(full, max_size, show_full))
    return all_hits


# ------------------------------------------------------------ recent

def parse_window(s):
    """Parse '24h', '7d', '30m' into seconds."""
    m = re.match(r"^(\d+)([smhd])$", s.strip().lower())
    if not m:
        raise ValueError(f"Invalid time window: {s} (use e.g. 30m, 24h, 7d)")
    n, unit = int(m.group(1)), m.group(2)
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return n * mult


def scan_recent(root, since_seconds, limit):
    now = time.time()
    cutoff = now - since_seconds if since_seconds else None
    results = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            mtime = st.st_mtime
            if cutoff is None or mtime >= cutoff:
                results.append((mtime, full, st.st_size))
    results.sort(key=lambda r: -r[0])
    return results[:limit] if limit else results


# ------------------------------------------------------------- output

def print_paths(hits, out_lines):
    out_lines.append(f"\n== ARTIFACT PATHS ({len(hits)}) ==")
    by_cat = {}
    for h in hits:
        by_cat.setdefault(h["category"], []).append(h)
    for cat in sorted(by_cat):
        out_lines.append(f"\n[{cat}]")
        for h in by_cat[cat]:
            out_lines.append(f"  {h['path']}  ({h['size']} bytes) — {h['desc']}")


def print_creds(hits, out_lines):
    out_lines.append(f"\n== CREDENTIAL-LOOKING STRINGS ({len(hits)}) ==")
    by_type = {}
    for h in hits:
        by_type.setdefault(h["type"], []).append(h)
    for t in sorted(by_type):
        out_lines.append(f"\n[{t}] ({len(by_type[t])})")
        for h in by_type[t]:
            out_lines.append(f"  {h['path']}: {h['value']}")


def print_recent(results, out_lines):
    out_lines.append(f"\n== RECENTLY MODIFIED FILES ({len(results)}) ==")
    for mtime, path, size in results:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))
        out_lines.append(f"  {ts}  {size:>10} bytes  {path}")


def main():
    parser = argparse.ArgumentParser(description="Forensic artifact and credential hunter")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_paths = sub.add_parser("paths", help="Find high-value artifact files by path pattern")
    p_paths.add_argument("root")
    p_paths.add_argument("-o", "--output")

    p_creds = sub.add_parser("creds", help="Scan file content for credential-looking strings")
    p_creds.add_argument("root")
    p_creds.add_argument("--show-full", action="store_true",
                          help="Show full matched values instead of redacted preview")
    p_creds.add_argument("--max-size", type=int, default=20 * 1024 * 1024,
                          help="Skip files larger than this (default 20MB, 0=no limit)")
    p_creds.add_argument("-o", "--output")

    p_recent = sub.add_parser("recent", help="List recently modified files")
    p_recent.add_argument("root")
    p_recent.add_argument("--since", default=None, help="Time window, e.g. 30m, 24h, 7d")
    p_recent.add_argument("--limit", type=int, default=100)
    p_recent.add_argument("-o", "--output")

    p_all = sub.add_parser("all", help="Run paths + creds + recent")
    p_all.add_argument("root")
    p_all.add_argument("--since", default="24h")
    p_all.add_argument("--show-full", action="store_true")
    p_all.add_argument("--max-size", type=int, default=20 * 1024 * 1024)
    p_all.add_argument("-o", "--output")

    args = parser.parse_args()
    if not os.path.isdir(args.root):
        print(f"Directory not found: {args.root}", file=sys.stderr)
        sys.exit(1)

    out_lines = []

    if args.cmd == "paths":
        hits = scan_paths(args.root)
        print_paths(hits, out_lines)

    elif args.cmd == "creds":
        hits = scan_creds(args.root, args.max_size, args.show_full)
        print_creds(hits, out_lines)

    elif args.cmd == "recent":
        since = parse_window(args.since) if args.since else None
        results = scan_recent(args.root, since, args.limit)
        print_recent(results, out_lines)

    elif args.cmd == "all":
        since = parse_window(args.since) if args.since else None
        hits = scan_paths(args.root)
        print_paths(hits, out_lines)
        cred_hits = scan_creds(args.root, args.max_size, args.show_full)
        print_creds(cred_hits, out_lines)
        recent = scan_recent(args.root, since, 100)
        print_recent(recent, out_lines)

    text_out = "\n".join(out_lines)
    print(text_out)

    if getattr(args, "output", None):
        with open(args.output, "w") as f:
            f.write(text_out + "\n")
        print(f"\n[+] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
