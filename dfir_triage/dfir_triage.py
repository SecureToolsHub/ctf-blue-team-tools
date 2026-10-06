#!/usr/bin/env python3
"""
dfir_triage.py — Rapid Live System Forensics & Evidence Collector for Blue Team CTF.

When you gain access to an unknown or compromised Linux machine during the competition,
run this script immediately to capture volatile state, persistence mechanisms, suspicious
processes, open connections, and attacker modifications before they change or get wiped.

Zero external dependencies (uses standard library only: os, sys, subprocess, shutil, tarfile, etc.).

Subcommands / Modes:
  quick      Collect vital signs in seconds (procs, conns, deleted exes, users, cron)
  full       Comprehensive triage (volatile state, persistence, SUID, tmp files, logs, ssh keys)
  diff       Compare two triage JSON outputs to see what changed

Usage:
    python3 dfir_triage.py quick
    python3 dfir_triage.py full -o /tmp/triage_evidence
    python3 dfir_triage.py full --tar /tmp/evidence.tar.gz
    python3 dfir_triage.py diff triage_1.json triage_2.json
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Terminal formatting
# ---------------------------------------------------------------------------

def ok(msg):  print(f"\033[92m[+]\033[0m {msg}")
def warn(msg): print(f"\033[93m[!]\033[0m {msg}")
def fail(msg): print(f"\033[91m[-]\033[0m {msg}")
def info(msg): print(f"\033[94m[~]\033[0m {msg}")
def hdr(msg):  print(f"\n\033[1m{'═'*65}\n  {msg}\n{'═'*65}\033[0m")
def subhdr(msg): print(f"\n\033[1;36m── {msg} ──\033[0m")


def run_cmd(cmd_list, timeout=15):
    """Run shell command safely and return stdout string."""
    try:
        r = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace"
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return f"[ERROR: {e}]"


def read_file_safe(path, max_len=100_000):
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(max_len)
    except Exception as e:
        return f"[ERROR reading {path}: {e}]"


def hash_file_sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Collector Functions
# ---------------------------------------------------------------------------

def collect_system_info():
    subhdr("System Information")
    info = {
        "hostname": platform.node(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "platform": platform.platform(),
        "datetime_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "uptime": run_cmd(["uptime"]),
        "os_release": read_file_safe("/etc/os-release"),
    }
    ok(f"Host: {info['hostname']} | Kernel: {info['kernel']} ({info['arch']})")
    ok(f"Uptime: {info['uptime']}")
    return info


def collect_network():
    subhdr("Network State & Connections")
    net = {}
    
    # Listening & established sockets
    if shutil.which("ss"):
        net["listening"] = run_cmd(["ss", "-tulpn"])
        net["established"] = run_cmd(["ss", "-tupn", "state", "established"])
    elif shutil.which("netstat"):
        net["listening"] = run_cmd(["netstat", "-tulpn"])
        net["established"] = run_cmd(["netstat", "-tupn"])
    else:
        net["listening"] = "[ss/netstat not found]"
        net["established"] = ""

    # Interfaces & IP routes
    net["ip_addr"] = run_cmd(["ip", "addr"]) if shutil.which("ip") else run_cmd(["ifconfig"])
    net["routes"] = run_cmd(["ip", "route"]) if shutil.which("ip") else run_cmd(["route", "-n"])
    net["arp"] = run_cmd(["ip", "neigh"]) if shutil.which("ip") else run_cmd(["arp", "-a"])
    net["resolv_conf"] = read_file_safe("/etc/resolv.conf")
    net["hosts"] = read_file_safe("/etc/hosts")

    # Quick inspection output
    lines = net["listening"].splitlines()
    ok(f"Listening sockets: {len(lines)} detected")
    for l in lines[:10]:
        print(f"    {l}")
    if len(lines) > 10:
        print(f"    ... [{len(lines)-10} more]")

    # Check for external connections
    est_lines = [l for l in net["established"].splitlines() if not l.startswith("Netid")]
    if est_lines:
        warn(f"Active Established Network Connections: {len(est_lines)}")
        for l in est_lines[:8]:
            print(f"    \033[93m{l}\033[0m")
    else:
        ok("No established external connections detected right now.")

    return net


def collect_processes():
    subhdr("Processes & Deleted Binary Execution")
    data = {}
    
    # Process table
    ps_aux = run_cmd(["ps", "auxf"]) if shutil.which("ps") else ""
    data["ps_aux"] = ps_aux

    # Check for deleted running executables (common stealth attacker trick!)
    deleted_procs = []
    suspicious_dirs = ["/tmp", "/dev/shm", "/var/tmp", "/run/user"]
    tmp_running_procs = []

    if os.path.isdir("/proc"):
        for pid_entry in os.listdir("/proc"):
            if not pid_entry.isdigit():
                continue
            pid = pid_entry
            exe_link = f"/proc/{pid}/exe"
            try:
                target = os.readlink(exe_link)
                if "(deleted)" in target:
                    deleted_procs.append({"pid": pid, "exe": target})
                for sdir in suspicious_dirs:
                    if target.startswith(sdir):
                        tmp_running_procs.append({"pid": pid, "exe": target})
            except (OSError, PermissionError):
                continue

    data["deleted_executables"] = deleted_procs
    data["tmp_running_executables"] = tmp_running_procs

    if deleted_procs:
        warn(f"ALERT: {len(deleted_procs)} processes running from DELETED files (common malware stealth):")
        for p in deleted_procs:
            print(f"    \033[91;1m[!] PID {p['pid']}: {p['exe']}\033[0m")
    else:
        ok("No running processes from deleted executables.")

    if tmp_running_procs:
        warn(f"ALERT: {len(tmp_running_procs)} processes running from /tmp or /dev/shm:")
        for p in tmp_running_procs:
            print(f"    \033[91;1m[!] PID {p['pid']}: {p['exe']}\033[0m")
    else:
        ok("No processes executing directly from /tmp or /dev/shm.")

    return data


def collect_users_and_privs():
    subhdr("Users, Sessions & Privileges")
    users_data = {}

    users_data["who"] = run_cmd(["w"])
    users_data["last"] = run_cmd(["last", "-n", "20"])
    users_data["lastlog"] = run_cmd(["lastlog"])
    users_data["passwd"] = read_file_safe("/etc/passwd")
    users_data["group"] = read_file_safe("/etc/group")

    # Parse passwd for UID 0 accounts
    uid0_accounts = []
    for line in users_data["passwd"].splitlines():
        parts = line.strip().split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid0_accounts.append(parts[0])

    users_data["uid0_accounts"] = uid0_accounts
    if len(uid0_accounts) > 1:
        warn(f"ALERT: Multiple UID 0 (root-equivalent) accounts found: {uid0_accounts}")
    else:
        ok(f"UID 0 accounts: {uid0_accounts}")

    # Check sudoers
    sudoers = read_file_safe("/etc/sudoers")
    sudoers_d = {}
    if os.path.isdir("/etc/sudoers.d"):
        for name in os.listdir("/etc/sudoers.d"):
            p = os.path.join("/etc/sudoers.d", name)
            if os.path.isfile(p):
                sudoers_d[name] = read_file_safe(p)
    users_data["sudoers"] = sudoers
    users_data["sudoers_d"] = sudoers_d

    ok(f"Current active sessions:\n    {users_data['who'].replace(chr(10), chr(10)+'    ')}")
    return users_data


def collect_persistence():
    subhdr("Persistence Mechanisms (Cron, Systemd, Startup)")
    pers = {}

    # Cron
    cron_files = {}
    cron_paths = ["/etc/crontab", "/etc/anacrontab"]
    for cp in cron_paths:
        if os.path.isfile(cp):
            cron_files[cp] = read_file_safe(cp)

    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.weekly", "/etc/cron.monthly",
                 "/var/spool/cron/crontabs", "/var/spool/cron"]
    for cd in cron_dirs:
        if os.path.isdir(cd):
            try:
                for entry in os.listdir(cd):
                    full = os.path.join(cd, entry)
                    if os.path.isfile(full):
                        cron_files[full] = read_file_safe(full)
            except PermissionError:
                cron_files[cd] = "[PermissionDenied]"

    pers["cron"] = cron_files
    ok(f"Cron locations inspected: {len(cron_files)} files found")
    for cp, content in cron_files.items():
        active_lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
        if active_lines:
            print(f"    \033[93m{cp}\033[0m: {len(active_lines)} active job(s)")
            for al in active_lines[:3]:
                print(f"      {al}")

    # Systemd timers & custom services
    if shutil.which("systemctl"):
        pers["systemd_timers"] = run_cmd(["systemctl", "list-timers", "--all"])
        pers["systemd_failed"] = run_cmd(["systemctl", "--failed"])
        
        # Check newly created or custom systemd unit files
        custom_units = []
        if os.path.isdir("/etc/systemd/system"):
            for root, _, files in os.walk("/etc/systemd/system"):
                for f in files:
                    if f.endswith((".service", ".timer", ".path")):
                        p = os.path.join(root, f)
                        try:
                            mtime = os.path.getmtime(p)
                            custom_units.append({"path": p, "mtime": datetime.datetime.fromtimestamp(mtime).isoformat()})
                        except OSError:
                            pass
            pers["custom_systemd_units"] = custom_units
            ok(f"Custom /etc/systemd/system units: {len(custom_units)}")

    # RC / init
    rc_local = "/etc/rc.local"
    if os.path.isfile(rc_local):
        pers["rc_local"] = read_file_safe(rc_local)
        warn(f"/etc/rc.local exists! Content preview:\n    {pers['rc_local'][:200]}")

    # User autostarts / shell profiles
    shell_profiles = ["/etc/profile", "/etc/bash.bashrc", "/etc/environment"]
    for sp in shell_profiles:
        if os.path.isfile(sp):
            pers[sp] = read_file_safe(sp)

    return pers


def collect_ssh_keys():
    subhdr("SSH Authorized Keys & Known Hosts")
    ssh_data = {}
    found_keys = []

    # Check root and home dirs
    check_dirs = ["/root"]
    if os.path.isdir("/home"):
        try:
            for u in os.listdir("/home"):
                check_dirs.append(os.path.join("/home", u))
        except PermissionError:
            pass

    for udir in check_dirs:
        ssh_dir = os.path.join(udir, ".ssh")
        auth_keys = os.path.join(ssh_dir, "authorized_keys")
        if os.path.isfile(auth_keys):
            content = read_file_safe(auth_keys)
            keys = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
            ssh_data[auth_keys] = keys
            for k in keys:
                found_keys.append({"path": auth_keys, "key_preview": k[:80]})

    if found_keys:
        warn(f"Found {len(found_keys)} authorized SSH key(s) across systems:")
        for k in found_keys:
            print(f"    \033[93m{k['path']}\033[0m: {k['key_preview']}...")
    else:
        ok("No active authorized_keys found in searched home directories.")

    return ssh_data


def collect_suid_and_tmp():
    subhdr("SUID Binaries & Suspicious Staging Directories")
    data = {}

    # SUID binaries
    suid_bins = []
    if shutil.which("find"):
        out = run_cmd(["find", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin",
                       "-perm", "-4000", "-type", "f"], timeout=20)
        suid_bins = out.splitlines()
    data["suid_binaries"] = suid_bins
    ok(f"Standard SUID binaries: {len(suid_bins)} found")

    # Check suspicious / writable locations for recently dropped files
    staging_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
    dropped_files = []
    for sdir in staging_dirs:
        if os.path.isdir(sdir):
            try:
                for root, _, files in os.walk(sdir):
                    for fname in files:
                        full = os.path.join(root, fname)
                        try:
                            st = os.stat(full)
                            dropped_files.append({
                                "path": full,
                                "size": st.st_size,
                                "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(),
                                "sha256": hash_file_sha256(full) if st.st_size < 5_000_000 else "large"
                            })
                        except OSError:
                            continue
            except PermissionError:
                pass

    data["staging_files"] = dropped_files
    if dropped_files:
        warn(f"Files currently sitting in /tmp, /var/tmp, or /dev/shm: {len(dropped_files)}")
        for df in dropped_files[:12]:
            print(f"    \033[93m{df['path']}\033[0m ({df['size']} bytes, modified {df['mtime']})")
        if len(dropped_files) > 12:
            print(f"    ... [{len(dropped_files)-12} more]")
    else:
        ok("No unexpected files found in /tmp, /var/tmp, or /dev/shm.")

    return data


def collect_shell_history():
    subhdr("Shell Histories")
    histories = {}
    check_dirs = ["/root"]
    if os.path.isdir("/home"):
        try:
            for u in os.listdir("/home"):
                check_dirs.append(os.path.join("/home", u))
        except PermissionError:
            pass

    for udir in check_dirs:
        for hist_name in [".bash_history", ".zsh_history", ".sh_history"]:
            hp = os.path.join(udir, hist_name)
            if os.path.isfile(hp):
                content = read_file_safe(hp, max_len=50_000)
                lines = [l for l in content.splitlines() if l.strip()]
                histories[hp] = lines[-30:] if len(lines) > 30 else lines
                ok(f"{hp}: {len(lines)} total command entries (capturing last {len(histories[hp])})")

    return histories

# ---------------------------------------------------------------------------
# Execution Modes
# ---------------------------------------------------------------------------

def run_triage(full=False):
    triage = {}
    triage["meta"] = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "collector_version": "1.0",
        "mode": "full" if full else "quick"
    }

    triage["system"] = collect_system_info()
    triage["network"] = collect_network()
    triage["processes"] = collect_processes()
    triage["users"] = collect_users_and_privs()
    triage["persistence"] = collect_persistence()

    if full:
        triage["ssh_keys"] = collect_ssh_keys()
        triage["suid_and_tmp"] = collect_suid_and_tmp()
        triage["shell_history"] = collect_shell_history()

    return triage


def cmd_quick(_args):
    hdr("DFIR QUICK TRIAGE — VITAL SIGNS")
    triage = run_triage(full=False)
    hdr("QUICK TRIAGE COMPLETE")
    print("  Run 'python3 dfir_triage.py full -o triage.json' to capture everything to disk.")


def cmd_full(args):
    hdr("DFIR FULL TRIAGE — COMPREHENSIVE INCIDENT EVIDENCE")
    triage = run_triage(full=True)

    # Output JSON
    out_path = args.output or f"triage_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out_path, "w") as f:
        json.dump(triage, f, indent=2)
    ok(f"Saved complete triage JSON to: {out_path} ({os.path.getsize(out_path):,} bytes)")

    # Optional tarball
    if args.tar:
        tar_path = args.tar
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(out_path, arcname=os.path.basename(out_path))
        ok(f"Created compressed evidence tarball: {tar_path}")

    hdr("FULL TRIAGE COMPLETE")


def cmd_diff(args):
    hdr("DFIR TRIAGE DIFF COMPARISON")
    with open(args.file1) as f1, open(args.file2) as f2:
        t1 = json.load(f1)
        t2 = json.load(f2)

    ok(f"File 1: {args.file1} ({t1.get('meta', {}).get('timestamp', '?')})")
    ok(f"File 2: {args.file2} ({t2.get('meta', {}).get('timestamp', '?')})")

    # Diff deleted procs
    p1 = {p["pid"]: p["exe"] for p in t1.get("processes", {}).get("deleted_executables", [])}
    p2 = {p["pid"]: p["exe"] for p in t2.get("processes", {}).get("deleted_executables", [])}
    new_deleted = set(p2) - set(p1)
    if new_deleted:
        warn(f"NEW deleted executables detected: {[f'{p}:{p2[p]}' for p in new_deleted]}")
    else:
        ok("No newly deleted executables between snapshots.")

    # Diff users
    u1 = set(t1.get("users", {}).get("uid0_accounts", []))
    u2 = set(t2.get("users", {}).get("uid0_accounts", []))
    if u2 - u1:
        warn(f"ALERT: New UID 0 accounts: {u2 - u1}")

    # Diff staging files
    f1_paths = {f["path"] for f in t1.get("suid_and_tmp", {}).get("staging_files", [])}
    f2_paths = {f["path"] for f in t2.get("suid_and_tmp", {}).get("staging_files", [])}
    added_files = f2_paths - f1_paths
    if added_files:
        warn(f"NEW files dropped in /tmp or /dev/shm ({len(added_files)}):")
        for af in added_files:
            print(f"    + {af}")
    else:
        ok("No new files added to /tmp staging directories.")


# ---------------------------------------------------------------------------
# Hunt & IOCs & Containment Subcommands
# ---------------------------------------------------------------------------

def check_ioc(name, condition, severity, ioc_val, technique):
    if condition:
        if severity == "CRITICAL":
            print(f"\033[91;1m[CRITICAL]\033[0m {name}")
        elif severity == "HIGH":
            print(f"\033[91m[HIGH]\033[0m {name}")
        else:
            print(f"\033[93m[WARN]\033[0m {name}")
        print(f"    Timestamp: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
        print(f"    Suggested IoC: {ioc_val} ({technique})")
        return True
    return False

def cmd_hunt_scenario(args):
    """Run a targeted hunt based on last year's Cyberkent scenario."""
    hdr("HUNT SCENARIO — CYBERKENT 4.0")
    
    # 1. Infostealer artifacts (Recycle Bin / unusual downloads)
    subhdr("Infostealer Artifacts")
    for d in ["/home", "/root"]:
        if not os.path.exists(d): continue
        for root_dir, dirs, files in os.walk(d):
            if "Trash" in root_dir or "Recycle Bin" in root_dir or "Downloads" in root_dir:
                for f in files:
                    if f.endswith(".exe") or "rufus" in f.lower():
                        check_ioc("Infostealer executable", True, "HIGH", os.path.join(root_dir, f), "T1059.003")

    # 2. Roundcube log files for RCE
    subhdr("Roundcube Log Analysis")
    for log_file in ["/var/log/roundcube/errors.log", "/var/log/mail.log", "/var/log/mail.err"]:
        rc_log = read_file_safe(log_file, 500000)
        if rc_log and not rc_log.startswith("[ERROR"):
            for line in rc_log.splitlines():
                if "<?php" in line or "Subject:" in line and ("$(" in line or "`" in line or "<?php" in line) or "POST" in line and "cmd=" in line:
                    check_ioc("Roundcube RCE Pattern Found", True, "CRITICAL", line.strip()[:100], "T1190")

    # 3. Recon scripts (linpeas / utils.sh)
    subhdr("Recon Scripts (LinPEAS / utils.sh)")
    for d in ["/tmp", "/var/tmp", "/dev/shm", "/home"]:
        if not os.path.exists(d): continue
        for root_dir, dirs, files in os.walk(d):
            for f in files:
                if "linpeas" in f.lower() or f == "utils.sh":
                    check_ioc(f"Recon script {f} found", True, "HIGH", os.path.join(root_dir, f), "T1082")

    # 4. SUID binaries that shouldn't have SUID
    subhdr("SUID Binaries")
    suid_bins = run_cmd(["find", "/", "-perm", "-4000", "-type", "f", "-xdev"], timeout=30)
    for b in suid_bins.splitlines():
        if "find" in b or "bash" in b or "python" in b or "nc" in b or "cp" in b or "mv" in b:
            check_ioc(f"Suspicious SUID binary: {b}", True, "CRITICAL", b, "T1548.001")

    # 5. Root crontab for reverse shells
    subhdr("Cron Reverse Shells")
    root_cron = run_cmd(["crontab", "-l", "-u", "root"]) + "\n" + read_file_safe("/etc/crontab")
    for line in root_cron.splitlines():
        if not line.strip().startswith("#"):
            if "nc " in line or "bash -i" in line or "socat " in line or "/dev/tcp/" in line or "curl " in line:
                check_ioc(f"Reverse shell in root crontab", True, "CRITICAL", line.strip(), "T1053.003")

    # 6. Systemd units for reverse shells
    subhdr("Systemd Unit Backdoors")
    for d in ["/etc/systemd/system", "/lib/systemd/system", "/run/systemd/system"]:
        if not os.path.exists(d): continue
        for root_dir, dirs, files in os.walk(d):
            for f in files:
                if f.endswith(".service"):
                    content = read_file_safe(os.path.join(root_dir, f), 10000)
                    if "nc " in content or "bash -i" in content or "socat " in content or "/dev/tcp/" in content:
                        check_ioc(f"Reverse shell in systemd unit: {f}", True, "CRITICAL", os.path.join(root_dir, f), "T1543.002")

    # 7. Chisel binary on filesystem
    subhdr("Chisel Binary Sweep")
    chisel_found = run_cmd(["find", "/", "-name", "chisel", "-type", "f", "-xdev"], timeout=30)
    for b in chisel_found.splitlines():
        check_ioc(f"Chisel proxy tool found", True, "CRITICAL", b, "T1090")

    # 8. Auth.log for new user creation, su/sudo abuse
    subhdr("Auth.log Analysis")
    auth_log = read_file_safe("/var/log/auth.log", 500000)
    for line in auth_log.splitlines():
        if "new user" in line or "useradd" in line:
            check_ioc("New user created in auth.log", True, "HIGH", line.strip()[:100], "T1136.001")
        if "sudo" in line and "COMMAND=" in line:
            if "chmod +s" in line or "nc " in line or "chisel" in line or "bash -i" in line:
                check_ioc("Suspicious sudo usage", True, "HIGH", line.strip()[:100], "T1548.003")
        if "FAILED su" in line:
             check_ioc("Failed su attempt", True, "WARN", line.strip()[:100], "T1548.003")

    # 9. iptables / ufw
    subhdr("Firewall Rules")
    iptables = run_cmd(["iptables", "-L", "-n"])
    for line in iptables.splitlines():
        if "ACCEPT" in line and ("dpt:" in line or "spt:" in line):
             if "22" not in line and "80" not in line and "443" not in line: # simplistic heuristic
                 check_ioc("Suspicious ACCEPT rule", True, "WARN", line.strip(), "T1562.004")

    # 10. /etc/passwd new shells
    subhdr("/etc/passwd Shells")
    passwd = read_file_safe("/etc/passwd")
    standard_users = {"root", "sync", "ubuntu", "kali", "kowalski"}
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[6] in ["/bin/bash", "/bin/sh", "/bin/zsh"]:
            if parts[0] not in standard_users:
                check_ioc(f"Unusual shell user: {parts[0]}", True, "WARN", parts[0], "T1078")

    # 11. SSH authorized_keys
    subhdr("SSH Authorized Keys")
    check_dirs = ["/root"]
    if os.path.isdir("/home"):
        check_dirs += [os.path.join("/home", u) for u in os.listdir("/home")]
    for d in check_dirs:
        auth_keys = os.path.join(d, ".ssh", "authorized_keys")
        keys = read_file_safe(auth_keys)
        if keys and not keys.startswith("[ERROR"):
            for k in keys.splitlines():
                if k.strip() and not k.startswith("#"):
                    check_ioc(f"SSH Key in {d}", True, "WARN", k[:50] + "...", "T1098.004")

    hdr("HUNT SCENARIO COMPLETE")


def cmd_quick_iocs(args):
    """Run the most time-efficient IOC sweep."""
    hdr("QUICK IOC SWEEP")
    
    iocs = []
    
    # 1. Last 24h auth.log failed logins
    auth = run_cmd(["grep", "Failed password", "/var/log/auth.log"])
    for line in auth.splitlines()[-50:]:
        m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            iocs.append(("Network/C2", m.group(1), "T1110 - Brute Force"))

    # 2. Syslog reverse shells
    syslog = run_cmd(["grep", "-E", "nc |bash -i|socat|/dev/tcp/", "/var/log/syslog"])
    for line in syslog.splitlines()[-20:]:
        iocs.append(("Command", line.strip()[:100], "T1059 - Command/Scripting"))

    # 3. All cron entries system-wide
    cron_paths = ["/etc/crontab"]
    if os.path.isdir("/var/spool/cron/crontabs"):
        cron_paths += [os.path.join("/var/spool/cron/crontabs", u) for u in os.listdir("/var/spool/cron/crontabs")]
    for p in cron_paths:
        cron_content = read_file_safe(p)
        if not cron_content.startswith("[ERROR"):
            for line in cron_content.splitlines():
                if not line.startswith("#") and line.strip():
                    iocs.append(("Cron", line.strip()[:100], "T1053 - Scheduled Task"))

    # 4. Systemd ExecStart suspicious
    sysd = run_cmd(["grep", "-R", "ExecStart=", "/etc/systemd/system/"])
    for line in sysd.splitlines():
        if "nc " in line or "bash -i" in line or "socat " in line:
            iocs.append(("Systemd", line.strip()[:100], "T1543.002 - Systemd Service"))

    # 5. SUID non-standard binaries
    suid = run_cmd(["find", "/usr/local/bin", "/opt", "/tmp", "/home", "-perm", "-4000", "-type", "f"], timeout=10)
    for line in suid.splitlines():
        iocs.append(("File", line.strip(), "T1548.001 - Setuid and Setgid"))

    # 6. Processes with unusual parent-child
    ps = run_cmd(["ps", "-eo", "pid,ppid,cmd"])
    for line in ps.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 3:
            cmd = parts[2]
            if "bash" in cmd or "sh" in cmd or "nc" in cmd:
                 if any(susp in cmd for susp in ["/dev/tcp", "-i", "socat"]):
                     iocs.append(("Process", cmd[:100], "T1059 - Command/Scripting"))

    # 7. Network connections to non-standard ports
    ss = run_cmd(["ss", "-tupn", "state", "established"])
    for line in ss.splitlines():
        if not line.startswith("Netid") and not line.startswith("[ERROR"):
            iocs.append(("Network", line.strip()[:100], "T1071 - App Layer Protocol"))
            
    print("\033[1;36m{:<15} | {:<40} | {:<30}\033[0m".format("TYPE", "VALUE", "TECHNIQUE"))
    print("-" * 90)
    for i_type, i_val, i_tech in set(iocs): # dedup
        print(f"{i_type:<15} | {i_val:<40} | {i_tech:<30}")
        
    hdr("IOC SWEEP COMPLETE")


def audit_log(action):
    msg = f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] CONTAINMENT ACTION: {action}"
    info(msg)
    try:
        with open("/var/log/dfir_containment.log", "a") as f:
            f.write(msg + "\n")
    except:
        pass


def cmd_containment(args):
    """Run emergency containment actions."""
    hdr("EMERGENCY CONTAINMENT")
    
    if args.block_ip:
        run_cmd(["iptables", "-A", "INPUT", "-s", args.block_ip, "-j", "DROP"])
        if shutil.which("ufw"):
            run_cmd(["ufw", "deny", "from", args.block_ip])
        ok(f"Blocked IP {args.block_ip} via iptables/ufw")
        audit_log(f"Blocked IP: {args.block_ip}")

    if args.kill_proc:
        try:
            pid = int(args.kill_proc)
            run_cmd(["kill", "-9", str(pid)])
            ok(f"Killed PID {pid}")
            audit_log(f"Killed PID: {pid}")
        except ValueError:
            run_cmd(["killall", "-9", args.kill_proc])
            ok(f"Killed processes named '{args.kill_proc}'")
            audit_log(f"Killed process by name: {args.kill_proc}")

    if args.kill_sessions:
        ps = run_cmd(["ps", "aux"])
        killed = 0
        for line in ps.splitlines():
            if "sshd:" in line and "@pts" in line:
                pid = line.split()[1]
                run_cmd(["kill", "-9", pid])
                killed += 1
        ok(f"Invalidated {killed} active SSH sessions")
        audit_log(f"Invalidated {killed} SSH sessions")

    if args.disable_user:
        run_cmd(["usermod", "-L", args.disable_user])
        run_cmd(["chage", "-E0", args.disable_user])
        ok(f"Disabled account: {args.disable_user}")
        audit_log(f"Disabled user account: {args.disable_user}")

    if args.fix_suid:
        if os.path.exists(args.fix_suid):
            run_cmd(["chmod", "u-s", args.fix_suid])
            run_cmd(["chmod", "g-s", args.fix_suid])
            ok(f"Removed SUID from {args.fix_suid}")
            audit_log(f"Removed SUID from: {args.fix_suid}")
        else:
            fail(f"File not found: {args.fix_suid}")

    if args.remove_cron:
        paths = ["/etc/crontab"]
        if os.path.isdir("/var/spool/cron/crontabs"):
            paths += [os.path.join("/var/spool/cron/crontabs", u) for u in os.listdir("/var/spool/cron/crontabs")]
        for p in paths:
            if os.path.isfile(p):
                run_cmd(["sed", "-i", f"/{args.remove_cron}/d", p])
        ok(f"Removed cron entries matching '{args.remove_cron}'")
        audit_log(f"Removed cron entry matching: {args.remove_cron}")

    if args.mask_unit:
        run_cmd(["systemctl", "stop", args.mask_unit])
        run_cmd(["systemctl", "mask", args.mask_unit])
        ok(f"Stopped and masked systemd unit: {args.mask_unit}")
        audit_log(f"Masked systemd unit: {args.mask_unit}")

    if not any([args.block_ip, args.kill_proc, args.kill_sessions, args.disable_user, args.fix_suid, args.remove_cron, args.mask_unit]):
        warn("No containment action specified. Use --help to see options.")
    
    hdr("CONTAINMENT COMPLETE")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Rapid Live System Forensics & Evidence Collector for Blue Team CTF"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("quick", help="Vital signs in seconds (procs, conns, deleted exes, users, cron)")

    p_full = sub.add_parser("full", help="Comprehensive evidence collection")
    p_full.add_argument("-o", "--output", help="Save triage JSON to file")
    p_full.add_argument("--tar", help="Create compressed .tar.gz bundle with the triage data")

    p_diff = sub.add_parser("diff", help="Compare two triage snapshots")
    p_diff.add_argument("file1", help="Baseline triage JSON")
    p_diff.add_argument("file2", help="Later triage JSON")

    # New commands
    sub.add_parser("hunt-scenario", help="Run a targeted hunt based on Cyberkent 4.0 scenario")
    
    sub.add_parser("quick-iocs", help="Run the most time-efficient IOC sweep")
    
    p_cont = sub.add_parser("containment", help="Run emergency containment actions")
    p_cont.add_argument("--block-ip", help="Block a given IP using iptables/ufw")
    p_cont.add_argument("--kill-proc", help="Kill process by name or PID")
    p_cont.add_argument("--kill-sessions", action="store_true", help="Invalidate all active SSH sessions")
    p_cont.add_argument("--disable-user", help="Disable a user account")
    p_cont.add_argument("--fix-suid", help="Remove SUID from file")
    p_cont.add_argument("--remove-cron", help="Remove cron entry by pattern")
    p_cont.add_argument("--mask-unit", help="Stop and mask systemd unit")

    args = parser.parse_args()

    dispatch = {
        "quick": cmd_quick,
        "full": cmd_full,
        "diff": cmd_diff,
        "hunt-scenario": cmd_hunt_scenario,
        "quick-iocs": cmd_quick_iocs,
        "containment": cmd_containment,
    }

    try:
        dispatch[args.cmd](args)
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(0)


if __name__ == "__main__":
    main()
