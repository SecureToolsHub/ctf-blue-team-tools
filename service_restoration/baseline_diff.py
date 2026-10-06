#!/usr/bin/env python3
"""
baseline_diff.py — Snapshot system state and diff two snapshots to
prove a service is actually restored (and see exactly what an
attacker touched).

Captures: listening ports, running processes, local users, cron
jobs, and SHA-256 hashes of files under chosen directories.

Usage:
    python3 baseline_diff.py snapshot -o before.json
    python3 baseline_diff.py snapshot -o before.json --hash-dirs /etc,/var/www
    python3 baseline_diff.py snapshot -o after.json --hash-dirs /etc,/var/www
    python3 baseline_diff.py diff before.json after.json
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import time

try:
    import psutil
except ImportError:
    psutil = None

DEFAULT_HASH_DIRS = ["/etc"]
DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024


def get_ports():
    if not psutil:
        return []
    ports = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status != "LISTEN":
                continue
            proc_name = ""
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            ports.append({"laddr": laddr, "pid": c.pid, "proc_name": proc_name})
    except (psutil.AccessDenied, AttributeError):
        pass
    return ports


def get_processes():
    if not psutil:
        return []
    procs = []
    for p in psutil.process_iter(["pid", "name", "exe", "username", "cmdline"]):
        try:
            info = p.info
            procs.append({
                "pid": info["pid"], "name": info["name"] or "",
                "exe": info["exe"] or "", "user": info["username"] or "",
                "cmdline": " ".join(info["cmdline"] or []),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def get_users():
    users = []
    passwd_path = "/etc/passwd"
    if os.path.isfile(passwd_path):
        try:
            with open(passwd_path, "r") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        users.append({
                            "username": parts[0], "uid": parts[2],
                            "gid": parts[3], "home": parts[5], "shell": parts[6],
                        })
        except OSError:
            pass
    return users


CRON_LOCATIONS = ["/etc/crontab"]
CRON_DIRS = ["/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"]


def get_cron():
    entries = []
    for path in CRON_LOCATIONS:
        if os.path.isfile(path):
            entries.extend(_read_cron_file(path))
    for d in CRON_DIRS:
        if os.path.isdir(d):
            try:
                for name in os.listdir(d):
                    full = os.path.join(d, name)
                    if os.path.isfile(full):
                        entries.extend(_read_cron_file(full))
            except PermissionError:
                pass
    return entries


def _read_cron_file(path):
    out = []
    try:
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.strip() and not line.strip().startswith("#"):
                    out.append({"source": path, "line": line})
    except (OSError, PermissionError):
        pass
    return out


def hash_file(path, max_size):
    try:
        if os.path.getsize(path) > max_size:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def get_file_hashes(dirs, max_size):
    hashes = {}
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for name in files:
                full = os.path.join(root, name)
                digest = hash_file(full, max_size)
                if digest:
                    hashes[full] = digest
    return hashes


def take_snapshot(hash_dirs, max_size):
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "ports": get_ports(),
        "processes": get_processes(),
        "users": get_users(),
        "cron": get_cron(),
        "file_hashes": get_file_hashes(hash_dirs, max_size),
    }


def cmd_snapshot(args):
    hash_dirs = [d.strip() for d in args.hash_dirs.split(",")] if args.hash_dirs else DEFAULT_HASH_DIRS
    print(f"[+] Snapshotting ports, processes, users, cron, and files under: {hash_dirs}",
          file=sys.stderr)
    if not psutil:
        print("[!] psutil not installed — ports/processes will be empty "
              "(pip install psutil)", file=sys.stderr)
    snap = take_snapshot(hash_dirs, args.max_file_size)
    with open(args.output, "w") as f:
        json.dump(snap, f, indent=2)
    print(f"[+] {len(snap['ports'])} ports, {len(snap['processes'])} processes, "
          f"{len(snap['users'])} users, {len(snap['cron'])} cron entries, "
          f"{len(snap['file_hashes'])} files hashed", file=sys.stderr)
    print(f"[+] Saved to {args.output}", file=sys.stderr)


# ----------------------------------------------------------------- diff

def diff_ports(before, after):
    b = {p["laddr"]: p for p in before}
    a = {p["laddr"]: p for p in after}
    added = [a[k] for k in a if k not in b]
    removed = [b[k] for k in b if k not in a]
    return added, removed


def diff_processes(before, after):
    b_names = {p["name"] for p in before}
    a_names = {p["name"] for p in after}
    new_names = a_names - b_names
    gone_names = b_names - a_names
    added = [p for p in after if p["name"] in new_names]
    removed = [p for p in before if p["name"] in gone_names]
    return added, removed


def diff_users(before, after):
    b = {u["username"]: u for u in before}
    a = {u["username"]: u for u in after}
    added = [a[k] for k in a if k not in b]
    removed = [b[k] for k in b if k not in a]
    return added, removed


def diff_cron(before, after):
    b = {(e["source"], e["line"]) for e in before}
    a = {(e["source"], e["line"]) for e in after}
    added = sorted(a - b)
    removed = sorted(b - a)
    return added, removed


def diff_files(before, after):
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(p for p in before if p in after and before[p] != after[p])
    return added, removed, changed


def cmd_diff(args):
    with open(args.before) as f:
        before = json.load(f)
    with open(args.after) as f:
        after = json.load(f)

    lines = []
    lines.append(f"BASELINE DIFF: {args.before} -> {args.after}")
    lines.append(f"  before: {before.get('timestamp')}   after: {after.get('timestamp')}")

    p_add, p_rem = diff_ports(before.get("ports", []), after.get("ports", []))
    lines.append(f"\n== PORTS == (+{len(p_add)} -{len(p_rem)})")
    for p in p_add:
        lines.append(f"  + {p['laddr']}  pid={p['pid']}  {p['proc_name']}")
    for p in p_rem:
        lines.append(f"  - {p['laddr']}  pid={p['pid']}  {p['proc_name']}")

    pr_add, pr_rem = diff_processes(before.get("processes", []), after.get("processes", []))
    lines.append(f"\n== PROCESSES (by name) == (+{len(pr_add)} -{len(pr_rem)})")
    for p in pr_add:
        lines.append(f"  + {p['name']}  pid={p['pid']}  user={p['user']}  cmd={p['cmdline'][:80]}")
    for p in pr_rem:
        lines.append(f"  - {p['name']}  pid={p['pid']}  user={p['user']}  cmd={p['cmdline'][:80]}")

    u_add, u_rem = diff_users(before.get("users", []), after.get("users", []))
    lines.append(f"\n== USERS == (+{len(u_add)} -{len(u_rem)})")
    for u in u_add:
        flag = "  <== UID 0 (root-equivalent)!" if u["uid"] == "0" else ""
        lines.append(f"  + {u['username']}  uid={u['uid']}  shell={u['shell']}{flag}")
    for u in u_rem:
        lines.append(f"  - {u['username']}  uid={u['uid']}  shell={u['shell']}")

    c_add, c_rem = diff_cron(before.get("cron", []), after.get("cron", []))
    lines.append(f"\n== CRON == (+{len(c_add)} -{len(c_rem)})")
    for src, line in c_add:
        lines.append(f"  + [{src}] {line}")
    for src, line in c_rem:
        lines.append(f"  - [{src}] {line}")

    f_add, f_rem, f_chg = diff_files(before.get("file_hashes", {}), after.get("file_hashes", {}))
    lines.append(f"\n== FILES == (+{len(f_add)} -{len(f_rem)} ~{len(f_chg)} changed)")
    for p in f_add:
        lines.append(f"  + {p}")
    for p in f_rem:
        lines.append(f"  - {p}")
    for p in f_chg:
        lines.append(f"  ~ {p}\n      before: {before['file_hashes'][p]}\n      after:  {after['file_hashes'][p]}")

    text_out = "\n".join(lines)
    print(text_out)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text_out + "\n")
        print(f"\n[+] Saved to {args.output}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="System baseline snapshot/diff tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_snap = sub.add_parser("snapshot", help="Capture current system state")
    p_snap.add_argument("-o", "--output", required=True)
    p_snap.add_argument("--hash-dirs", help="Comma-separated dirs to hash (default: /etc)")
    p_snap.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE,
                         help="Skip files larger than this many bytes")
    p_snap.set_defaults(func=cmd_snapshot)

    p_diff = sub.add_parser("diff", help="Compare two snapshots")
    p_diff.add_argument("before")
    p_diff.add_argument("after")
    p_diff.add_argument("-o", "--output")
    p_diff.set_defaults(func=cmd_diff)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
