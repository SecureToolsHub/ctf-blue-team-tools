#!/usr/bin/env python3
"""
Firewall Manager - Blue Team CTF Toolset

Manages iptables and ufw rules for infrastructure protection.
Provides fast, idempotent commands to audit, baseline, block, and monitor traffic.

Requirements:
- Linux environment
- Root privileges (sudo)
- iptables / ufw
"""

import os
import sys
import argparse
import subprocess
import datetime
import re
import shutil
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

# Constants
LOG_FILE = "/var/log/firewall_manager.log"
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")

KNOWN_BAD_IPS = [
    ("31.220.94.79", "Known C2/RCE origin"),
    ("194.163.131.46", "Known Mythic C2"),
]

SERVICE_PORTS = {
    "ssh": [22], "http": [80], "https": [443],
    "mysql": [3306], "postgresql": [5432],
    "elasticsearch": [9200, 9300], "kibana": [5601],
    "logstash": [5044, 9600], "splunk": [8000, 8089],
    "redis": [6379], "mongodb": [27017],
    "gitlab": [80, 443, 22], "roundcube": [80, 443],
    "smtp": [25, 587, 465], "imap": [143, 993],
}

# ANSI Colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_c(text: str, color: str = Colors.RESET) -> None:
    """Print colored text."""
    print(f"{color}{text}{Colors.RESET}")

def run_cmd(cmd: List[str], check: bool = True, suppress_output: bool = False) -> subprocess.CompletedProcess:
    """Run a shell command safely."""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check and result.returncode != 0:
            if not suppress_output:
                print_c(f"[-] Command failed: {' '.join(cmd)}", Colors.RED)
                print_c(result.stderr, Colors.RED)
            sys.exit(result.returncode)
        return result
    except FileNotFoundError:
        print_c(f"[-] Command not found: {cmd[0]}. Please ensure it is installed.", Colors.RED)
        sys.exit(1)

def ensure_root() -> None:
    """Ensure script is running as root."""
    if os.geteuid() != 0:
        print_c("[-] This script must be run as root (sudo).", Colors.RED)
        sys.exit(1)

def audit_log(action: str, rule: str) -> None:
    """Log an action to the audit log."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user = os.environ.get('SUDO_USER', os.environ.get('USER', 'root'))
    log_entry = f"[{timestamp}] USER={user} ACTION={action} RULE='{rule}'\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(log_entry)
    except IOError as e:
        print_c(f"[-] Could not write to log file: {e}", Colors.RED)

def create_backup(label: str = "auto") -> str:
    """Create an iptables backup."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"firewall_backup_{timestamp}_{label}.rules")
    
    result = run_cmd(["iptables-save"])
    with open(backup_file, "w") as f:
        f.write(result.stdout)
    
    print_c(f"[+] Backup created at {backup_file}", Colors.CYAN)
    return backup_file

def check_ufw_active() -> bool:
    """Check if UFW is installed and active."""
    if shutil.which("ufw"):
        res = run_cmd(["ufw", "status"], check=False, suppress_output=True)
        return "Status: active" in res.stdout
    return False

# Commands
def cmd_status(args: argparse.Namespace) -> None:
    """Show current firewall state."""
    print_c(f"\n{Colors.BOLD}=== IPTABLES STATUS ==={Colors.RESET}")
    result = run_cmd(["iptables", "-L", "-n", "-v"])
    
    for line in result.stdout.splitlines():
        if "0.0.0.0/0" in line and "ACCEPT" in line:
            print_c(line, Colors.YELLOW)
        elif "DROP" in line or "REJECT" in line:
            print_c(line, Colors.GREEN)
        else:
            print(line)

    if check_ufw_active():
        print_c(f"\n{Colors.BOLD}=== UFW STATUS ==={Colors.RESET}")
        run_cmd(["ufw", "status", "verbose"], check=False)

def cmd_audit(args: argparse.Namespace) -> None:
    """Audit current rules for security gaps."""
    print_c(f"\n{Colors.BOLD}=== FIREWALL AUDIT ==={Colors.RESET}")
    result = run_cmd(["iptables-save"])
    lines = result.stdout.splitlines()
    
    issues = []
    
    # Check Default Policies
    input_drop = False
    output_log = False
    
    for line in lines:
        if line.startswith(":INPUT"):
            if "DROP" not in line:
                issues.append(("CRITICAL", "Default INPUT policy is not DROP.", line))
            else:
                input_drop = True
        elif "-A OUTPUT" in line and ("LOG" in line or "log" in line):
            output_log = True
        elif "-A INPUT" in line and "ACCEPT" in line and "0.0.0.0/0" in line and "state ESTABLISHED" not in line:
            issues.append(("HIGH", "Overly permissive rule allows ALL traffic.", line))
            
    if not output_log:
        issues.append(("MEDIUM", "No OUTPUT logging rule found. Suspicious outbound traffic won't be logged.", ""))
        
    for sev, msg, rule in issues:
        color = Colors.RED if sev in ["CRITICAL", "HIGH"] else Colors.YELLOW
        print_c(f"[{sev}] {msg}", color)
        if rule:
            print(f"      Rule: {rule}")
            
    if not issues:
        print_c("[+] No major security gaps found in current ruleset.", Colors.GREEN)

def cmd_baseline(args: argparse.Namespace) -> None:
    """Apply a secure default Blue Team firewall ruleset."""
    if not args.dry_run:
        create_backup("pre_baseline")
    
    services = args.services.split(",") if args.services else []
    
    commands = [
        # Flush existing rules
        ["iptables", "-F"],
        ["iptables", "-X"],
        # Default policies
        ["iptables", "-P", "INPUT", "DROP"],
        ["iptables", "-P", "FORWARD", "DROP"],
        ["iptables", "-P", "OUTPUT", "ACCEPT"],
        # Allow loopback
        ["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
        ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
        # Allow ESTABLISHED/RELATED
        ["iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
    ]
    
    # Allow SSH only from management IP
    if args.management_ip:
        commands.append(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", args.management_ip, "-j", "ACCEPT"])
        commands.append(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"])
        
    # Allow Services
    for svc in services:
        svc = svc.strip()
        if svc in SERVICE_PORTS:
            for port in SERVICE_PORTS[svc]:
                commands.append(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"])
        else:
            print_c(f"[-] Warning: Unknown service '{svc}', skipping.", Colors.YELLOW)
            
    # Add logging for dropped packets
    commands.append(["iptables", "-A", "INPUT", "-m", "limit", "--limit", "5/min", "-j", "LOG", "--log-prefix", "iptables_INPUT_DROP: ", "--log-level", "7"])
    
    for cmd in commands:
        if args.dry_run:
            print(" ".join(cmd))
        else:
            run_cmd(cmd)
            
    if not args.dry_run:
        print_c("[+] Baseline ruleset applied successfully.", Colors.GREEN)
        audit_log("baseline", f"services={args.services}, mgt_ip={args.management_ip}")

def _block_ip(ip: str, direction: str, comment: str) -> None:
    """Helper to block a specific IP."""
    print_c(f"[*] Blocking IP {ip} (Direction: {direction})", Colors.BLUE)
    
    cmds = []
    if direction in ["in", "both"]:
        # Check idempotency
        check = run_cmd(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], check=False, suppress_output=True)
        if check.returncode != 0:
            cmds.append(["iptables", "-I", "INPUT", "-s", ip, "-m", "comment", "--comment", comment, "-j", "DROP"])
        else:
            print_c(f"    Already blocked inbound.", Colors.YELLOW)
            
    if direction in ["out", "both"]:
        check = run_cmd(["iptables", "-C", "OUTPUT", "-d", ip, "-j", "DROP"], check=False, suppress_output=True)
        if check.returncode != 0:
            cmds.append(["iptables", "-I", "OUTPUT", "-d", ip, "-m", "comment", "--comment", comment, "-j", "DROP"])
        else:
            print_c(f"    Already blocked outbound.", Colors.YELLOW)
            
    for cmd in cmds:
        run_cmd(cmd)
        audit_log("block-ip", " ".join(cmd))
        
    if check_ufw_active():
        if direction in ["in", "both"]:
            run_cmd(["ufw", "deny", "from", ip])
        if direction in ["out", "both"]:
            run_cmd(["ufw", "deny", "out", "to", ip])
            
    print_c(f"[+] Successfully applied block for {ip}.", Colors.GREEN)

def cmd_block_ip(args: argparse.Namespace) -> None:
    """Block a specific IP."""
    create_backup(f"pre_block_{args.ip}")
    _block_ip(args.ip, args.direction, args.comment)

def cmd_block_list(args: argparse.Namespace) -> None:
    """Block multiple IPs from a file or defaults."""
    create_backup("pre_block_list")
    ips_to_block = []
    
    if args.append_defaults:
        for ip, reason in KNOWN_BAD_IPS:
            ips_to_block.append((ip, reason))
            
    if args.file:
        try:
            with open(args.file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips_to_block.append((line, "File Import"))
        except IOError as e:
            print_c(f"[-] Could not read file: {e}", Colors.RED)
            
    for ip, reason in ips_to_block:
        _block_ip(ip, "both", reason)

def cmd_unblock_ip(args: argparse.Namespace) -> None:
    """Remove block rules for an IP."""
    create_backup(f"pre_unblock_{args.ip}")
    
    print_c(f"[*] Checking rules for {args.ip}...", Colors.BLUE)
    
    # Inbound
    while run_cmd(["iptables", "-C", "INPUT", "-s", args.ip, "-j", "DROP"], check=False, suppress_output=True).returncode == 0:
        run_cmd(["iptables", "-D", "INPUT", "-s", args.ip, "-j", "DROP"])
        print_c(f"    Removed inbound DROP rule for {args.ip}", Colors.GREEN)
        audit_log("unblock-ip", f"iptables -D INPUT -s {args.ip} -j DROP")
        
    # Outbound
    while run_cmd(["iptables", "-C", "OUTPUT", "-d", args.ip, "-j", "DROP"], check=False, suppress_output=True).returncode == 0:
        run_cmd(["iptables", "-D", "OUTPUT", "-d", args.ip, "-j", "DROP"])
        print_c(f"    Removed outbound DROP rule for {args.ip}", Colors.GREEN)
        audit_log("unblock-ip", f"iptables -D OUTPUT -d {args.ip} -j DROP")
        
    if check_ufw_active():
        # UFW deletion requires rule number, complex to script idempotently quickly.
        # Fallback to general delete (might prompt or need multiple deletes)
        run_cmd(["ufw", "delete", "deny", "from", args.ip], check=False, suppress_output=True)
        run_cmd(["ufw", "delete", "deny", "out", "to", args.ip], check=False, suppress_output=True)
        print_c(f"    Cleaned up any UFW deny rules for {args.ip}", Colors.GREEN)

def cmd_allow_port(args: argparse.Namespace) -> None:
    """Safely open a port."""
    create_backup(f"pre_allow_port_{args.port}")
    
    cmd = ["iptables", "-I", "INPUT", "-p", args.proto, "--dport", str(args.port)]
    if args.from_ip:
        cmd.extend(["-s", args.from_ip])
    cmd.extend(["-m", "comment", "--comment", args.comment, "-j", "ACCEPT"])
    
    check_cmd = [c for c in cmd]
    check_cmd[1] = "-C"
    
    if run_cmd(check_cmd, check=False, suppress_output=True).returncode == 0:
        print_c(f"[*] Port {args.port}/{args.proto} is already allowed.", Colors.YELLOW)
        return
        
    run_cmd(cmd)
    audit_log("allow-port", " ".join(cmd))
    print_c(f"[+] Allowed port {args.port}/{args.proto}.", Colors.GREEN)

def cmd_deny_outbound(args: argparse.Namespace) -> None:
    """Block specific outbound connections."""
    create_backup("pre_deny_outbound")
    if args.ip:
        _block_ip(args.ip, "out", "Deny Outbound IP")
    elif args.port:
        cmd = ["iptables", "-I", "OUTPUT", "-p", "tcp", "--dport", str(args.port), "-j", "DROP"]
        run_cmd(cmd)
        audit_log("deny-outbound", f"port {args.port}")
        print_c(f"[+] Blocked outbound tcp traffic on port {args.port}", Colors.GREEN)
    elif args.except_ports:
        print_c("[*] This will DROP all outbound traffic EXCEPT for the specified ports.", Colors.YELLOW)
        confirm = input("Are you sure? [y/N]: ")
        if confirm.lower() != 'y':
            return
            
        allowed_ports = args.except_ports.split(",")
        run_cmd(["iptables", "-P", "OUTPUT", "DROP"])
        run_cmd(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        run_cmd(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        
        for port in allowed_ports:
            run_cmd(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", port.strip(), "-j", "ACCEPT"])
            run_cmd(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", port.strip(), "-j", "ACCEPT"])
            
        audit_log("deny-outbound", f"except ports {args.except_ports}")
        print_c("[+] Outbound lockdown applied.", Colors.GREEN)

def cmd_save(args: argparse.Namespace) -> None:
    """Persist rules across reboots."""
    create_backup("manual_save")
    
    if os.path.exists("/etc/iptables"):
        run_cmd(["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
        print_c("[+] Saved rules to /etc/iptables/rules.v4", Colors.GREEN)
    else:
        print_c("[-] /etc/iptables not found, rules not saved to system persistent store.", Colors.YELLOW)
        
    audit_log("save", "saved current ruleset")

def cmd_restore(args: argparse.Namespace) -> None:
    """Restore from backup."""
    target_file = None
    
    if args.file:
        target_file = args.file
    elif args.latest:
        if not os.path.exists(BACKUP_DIR):
            print_c("[-] No backup directory found.", Colors.RED)
            sys.exit(1)
        files = [os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR) if os.path.isfile(os.path.join(BACKUP_DIR, f))]
        if not files:
            print_c("[-] No backups found.", Colors.RED)
            sys.exit(1)
        target_file = max(files, key=os.path.getctime)
        
    if not target_file or not os.path.exists(target_file):
        print_c("[-] Backup file not specified or doesn't exist.", Colors.RED)
        sys.exit(1)
        
    run_cmd(["sh", "-c", f"iptables-restore < {target_file}"])
    audit_log("restore", f"Restored from {target_file}")
    print_c(f"[+] Restored iptables rules from {target_file}", Colors.GREEN)

def cmd_log_watch(args: argparse.Namespace) -> None:
    """Monitor firewall drop log in real time."""
    print_c("[*] Monitoring /var/log/kern.log for firewall drops... (Ctrl+C to stop)", Colors.CYAN)
    try:
        process = subprocess.Popen(["tail", "-f", "/var/log/kern.log"], stdout=subprocess.PIPE, text=True)
        if process.stdout is None:
            return
            
        for line in iter(process.stdout.readline, ''):
            if "iptables" in line or "DROP" in line:
                # Basic parsing
                src = re.search(r'SRC=([0-9\.]+)', line)
                dst_port = re.search(r'DPT=([0-9]+)', line)
                proto = re.search(r'PROTO=([A-Z]+)', line)
                
                src_ip = src.group(1) if src else "Unknown"
                port = dst_port.group(1) if dst_port else "Unknown"
                pr = proto.group(1) if proto else "Unknown"
                
                print_c(f"DROP | SRC: {src_ip:<15} | DPT: {port:<5} | PROTO: {pr}", Colors.YELLOW)
                
    except KeyboardInterrupt:
        print_c("\n[+] Stopped monitoring.", Colors.GREEN)
        sys.exit(0)

def main() -> None:
    ensure_root()
    parser = argparse.ArgumentParser(description="Firewall Manager - Blue Team CTF Toolset")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    parser_status = subparsers.add_parser("status", help="Show current firewall state")
    
    # audit
    parser_audit = subparsers.add_parser("audit", help="Audit current rules for security gaps")
    
    # baseline
    parser_baseline = subparsers.add_parser("baseline", help="Apply a secure default ruleset")
    parser_baseline.add_argument("--services", help="Comma-separated list of services to allow (e.g., ssh,http,mysql)")
    parser_baseline.add_argument("--management-ip", help="IP allowed for SSH management")
    parser_baseline.add_argument("--dry-run", action="store_true", help="Show rules without applying")
    
    # block-ip
    parser_block_ip = subparsers.add_parser("block-ip", help="Block a specific IP address")
    parser_block_ip.add_argument("ip", help="IP address to block")
    parser_block_ip.add_argument("--direction", choices=["in", "out", "both"], default="both", help="Traffic direction")
    parser_block_ip.add_argument("--comment", default="Manual Block", help="Comment/Reason")
    
    # block-list
    parser_block_list = subparsers.add_parser("block-list", help="Block multiple IPs from a file")
    parser_block_list.add_argument("--file", help="File containing IPs (one per line)")
    parser_block_list.add_argument("--append-defaults", action="store_true", help="Add pre-populated known-bad list")
    
    # unblock-ip
    parser_unblock_ip = subparsers.add_parser("unblock-ip", help="Remove a block rule for an IP")
    parser_unblock_ip.add_argument("ip", help="IP address to unblock")
    
    # allow-port
    parser_allow_port = subparsers.add_parser("allow-port", help="Safely open a port")
    parser_allow_port.add_argument("port", type=int, help="Port number")
    parser_allow_port.add_argument("--proto", choices=["tcp", "udp"], default="tcp", help="Protocol")
    parser_allow_port.add_argument("--from-ip", help="Restrict to specific source IP/CIDR")
    parser_allow_port.add_argument("--comment", default="Manual Allow", help="Comment for the rule")
    
    # deny-outbound
    parser_deny_outbound = subparsers.add_parser("deny-outbound", help="Block specific outbound connections")
    parser_deny_outbound.add_argument("--ip", help="Block outbound to this IP")
    parser_deny_outbound.add_argument("--port", type=int, help="Block outbound on this port")
    parser_deny_outbound.add_argument("--except-ports", help="Comma-separated ports to allow (blocks everything else)")
    
    # save
    parser_save = subparsers.add_parser("save", help="Persist rules across reboots")
    
    # restore
    parser_restore = subparsers.add_parser("restore", help="Restore from backup")
    parser_restore.add_argument("--file", help="Specific backup file to restore")
    parser_restore.add_argument("--latest", action="store_true", help="Restore the latest auto-backup")
    
    # log-watch
    parser_log_watch = subparsers.add_parser("log-watch", help="Monitor firewall drop log in real time")
    
    args = parser.parse_args()
    
    commands = {
        "status": cmd_status,
        "audit": cmd_audit,
        "baseline": cmd_baseline,
        "block-ip": cmd_block_ip,
        "block-list": cmd_block_list,
        "unblock-ip": cmd_unblock_ip,
        "allow-port": cmd_allow_port,
        "deny-outbound": cmd_deny_outbound,
        "save": cmd_save,
        "restore": cmd_restore,
        "log-watch": cmd_log_watch,
    }
    
    commands[args.command](args)

if __name__ == "__main__":
    main()
