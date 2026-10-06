#!/usr/bin/env python3
import argparse
import json
import logging
import os
import pwd
import re
import shlex
import stat
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Colored output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Known safe SUID whitelist
SUID_WHITELIST = {
    'ping', 'su', 'sudo', 'passwd', 'chsh', 'chfn', 'newgrp', 'mount', 'umount',
    'fusermount', 'pkexec', 'polkit-agent-helper-1', 'unix_chkpwd', 'ssh-agent',
    'Xorg', 'at', 'crontab', 'screen', 'wall', 'write', 'expiry', 'chage',
    'gpasswd', 'newuidmap', 'newgidmap', 'traceroute', 'traceroute6',
    'ping6', 'dbus-daemon-launch-helper', 'sudoedit', 'pt_chown'
}

# Suspicious patterns in ExecStart/cron/rc.local
SUSPICIOUS_PATTERNS = [
    r'bash\s+-i', r'/dev/tcp', r'nc\s+-e', r'ncat\s+-e', r'socat\s+exec',
    r'python\s+-c\s+[\'"]import socket', r'perl\s+-e', r'ruby\s+-e',
    r'curl.*?\|\s*bash', r'wget.*?\|\s*bash', r'chisel', r'linpeas'
]

class Finding:
    def __init__(self, category: str, severity: str, description: str, details: str, remediation: str = ""):
        self.category = category
        self.severity = severity
        self.description = description
        self.details = details
        self.remediation = remediation

    def to_dict(self) -> Dict[str, str]:
        return {
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "details": self.details,
            "remediation": self.remediation
        }

class PersistenceHunter:
    def __init__(self):
        self.findings: List[Finding] = []
        self.suspicious_regex = re.compile('|'.join(SUSPICIOUS_PATTERNS), re.IGNORECASE)

    def print_findings(self) -> None:
        """Prints all findings to the console with colored severity."""
        for finding in self.findings:
            color = Colors.OKGREEN
            if finding.severity == "CRITICAL":
                color = Colors.FAIL + Colors.BOLD
            elif finding.severity == "HIGH":
                color = Colors.FAIL
            elif finding.severity == "MEDIUM":
                color = Colors.WARNING
            elif finding.severity == "INFO":
                color = Colors.OKBLUE

            print(f"{color}[{finding.severity}] {finding.category}: {finding.description}{Colors.ENDC}")
            if finding.details:
                print(f"    Details: {finding.details}")
            if finding.remediation:
                print(f"    Remediation: {finding.remediation}")
            print()

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def scan_suid(self) -> None:
        """Scans for non-standard SUID/SGID binaries."""
        try:
            output = subprocess.check_output(['find', '/', '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')'], stderr=subprocess.DEVNULL)
            paths = output.decode('utf-8').splitlines()
            for p in paths:
                filename = os.path.basename(p)
                if filename not in SUID_WHITELIST:
                    self.add_finding(Finding(
                        category="SUID/SGID",
                        severity="HIGH",
                        description=f"Non-standard SUID/SGID binary found: {p}",
                        details=p,
                        remediation=f"chmod -s {p}"
                    ))
        except Exception as e:
            logging.error(f"Error scanning SUID/SGID files: {e}")

    def _check_content_for_suspicious(self, content: str, filepath: str, category: str) -> None:
        for line in content.splitlines():
            if self.suspicious_regex.search(line):
                self.add_finding(Finding(
                    category=category,
                    severity="CRITICAL",
                    description=f"Suspicious pattern found in {filepath}",
                    details=line.strip(),
                    remediation=f"Review and edit {filepath}"
                ))

    def scan_cron(self) -> None:
        """Scans cron jobs for suspicious patterns."""
        cron_paths = [
            "/etc/crontab",
            "/var/spool/cron/crontabs"
        ]
        
        # Files directly
        if os.path.exists("/etc/crontab"):
            try:
                with open("/etc/crontab", "r", errors="ignore") as f:
                    self._check_content_for_suspicious(f.read(), "/etc/crontab", "Cron")
            except Exception as e:
                logging.error(f"Error reading /etc/crontab: {e}")
                
        # Directories
        dirs_to_check = ["/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs"]
        for d in dirs_to_check:
            if os.path.exists(d):
                for root, _, files in os.walk(d):
                    for file in files:
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, "r", errors="ignore") as f:
                                self._check_content_for_suspicious(f.read(), filepath, "Cron")
                        except Exception as e:
                            logging.error(f"Error reading cron file {filepath}: {e}")

    def scan_systemd(self) -> None:
        """Scans systemd units for suspicious patterns."""
        dirs_to_check = ["/etc/systemd/system/", "/lib/systemd/system/", "/run/systemd/system/"]
        for d in dirs_to_check:
            if os.path.exists(d):
                for root, _, files in os.walk(d):
                    for file in files:
                        if file.endswith(".service") or file.endswith(".timer"):
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, "r", errors="ignore") as f:
                                    self._check_content_for_suspicious(f.read(), filepath, "Systemd")
                            except Exception as e:
                                pass

    def scan_ssh(self) -> None:
        """Scans SSH authorized_keys files."""
        for user in pwd.getpwall():
            home_dir = user.pw_dir
            auth_keys = os.path.join(home_dir, ".ssh", "authorized_keys")
            if os.path.exists(auth_keys):
                self.add_finding(Finding(
                    category="SSH",
                    severity="INFO",
                    description=f"SSH authorized_keys found for user {user.pw_name}",
                    details=auth_keys,
                    remediation=f"Review keys in {auth_keys}"
                ))

    def scan_bash_configs(self) -> None:
        """Scans user bash configurations."""
        for user in pwd.getpwall():
            home_dir = user.pw_dir
            for rc_file in [".bashrc", ".profile", ".bash_profile"]:
                filepath = os.path.join(home_dir, rc_file)
                if os.path.exists(filepath):
                    try:
                        with open(filepath, "r", errors="ignore") as f:
                            self._check_content_for_suspicious(f.read(), filepath, "Shell Profile")
                    except Exception:
                        pass

    def scan_rc_local(self) -> None:
        """Scans rc.local and init.d scripts."""
        if os.path.exists("/etc/rc.local"):
            try:
                with open("/etc/rc.local", "r", errors="ignore") as f:
                    self._check_content_for_suspicious(f.read(), "/etc/rc.local", "Startup Script")
            except Exception:
                pass
                
        if os.path.exists("/etc/init.d"):
            for file in os.listdir("/etc/init.d"):
                filepath = os.path.join("/etc/init.d", file)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, "r", errors="ignore") as f:
                            self._check_content_for_suspicious(f.read(), filepath, "Startup Script")
                    except Exception:
                        pass

    def scan_sudoers(self) -> None:
        """Scans sudoers configuration for NOPASSWD."""
        def check_sudoers_file(filepath: str) -> None:
            if not os.path.exists(filepath):
                return
            try:
                with open(filepath, "r", errors="ignore") as f:
                    content = f.read()
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if "NOPASSWD" in line or "ALL=(ALL:ALL) ALL" in line or "ALL=(ALL) ALL" in line:
                                self.add_finding(Finding(
                                    category="Sudoers",
                                    severity="HIGH",
                                    description=f"Permissive sudoers entry found in {filepath}",
                                    details=line,
                                    remediation=f"Review and restrict entry in {filepath}"
                                ))
            except Exception:
                pass

        check_sudoers_file("/etc/sudoers")
        if os.path.exists("/etc/sudoers.d"):
            for file in os.listdir("/etc/sudoers.d"):
                check_sudoers_file(os.path.join("/etc/sudoers.d", file))

    def scan_users(self) -> None:
        """Scans for UID 0 users and recently added shell users."""
        try:
            for user in pwd.getpwall():
                if user.pw_uid == 0 and user.pw_name != "root":
                    self.add_finding(Finding(
                        category="Users",
                        severity="CRITICAL",
                        description=f"Non-root user with UID 0 found: {user.pw_name}",
                        details=f"User: {user.pw_name}, UID: {user.pw_uid}",
                        remediation=f"Change UID of {user.pw_name} or remove user"
                    ))
                if user.pw_shell not in ["/bin/false", "/usr/sbin/nologin", "/bin/sync"]:
                    # Just an informational check, wouldn't flag standard users normally unless looking for anomalies
                    pass
        except Exception:
            pass

    def scan_processes(self) -> None:
        """Scans running processes for suspicious commands."""
        try:
            output = subprocess.check_output(['ps', '-eo', 'pid,user,cmd'], stderr=subprocess.DEVNULL)
            lines = output.decode('utf-8').splitlines()[1:]
            for line in lines:
                parts = line.split(None, 2)
                if len(parts) == 3:
                    pid, user, cmd = parts
                    if self.suspicious_regex.search(cmd):
                        self.add_finding(Finding(
                            category="Process",
                            severity="CRITICAL",
                            description=f"Suspicious process running",
                            details=f"PID: {pid}, User: {user}, Cmd: {cmd}",
                            remediation=f"kill -9 {pid}"
                        ))
        except Exception:
            pass

    def scan_listeners(self) -> None:
        """Scans for unexpected listening ports using ss."""
        try:
            output = subprocess.check_output(['ss', '-tulnp'], stderr=subprocess.DEVNULL)
            # Just look for suspicious patterns in the whole output
            for line in output.decode('utf-8').splitlines():
                if self.suspicious_regex.search(line) or 'bash' in line or 'nc ' in line or 'socat' in line:
                    self.add_finding(Finding(
                        category="Network",
                        severity="HIGH",
                        description="Suspicious listening port / process found",
                        details=line.strip(),
                        remediation="Investigate process with ss/netstat and kill"
                    ))
        except Exception:
            pass

    def run_all_scans(self) -> None:
        """Executes all persistence scanning modules."""
        self.findings = [] # reset
        self.scan_suid()
        self.scan_cron()
        self.scan_systemd()
        self.scan_ssh()
        self.scan_bash_configs()
        self.scan_rc_local()
        self.scan_sudoers()
        self.scan_users()
        self.scan_processes()
        self.scan_listeners()

    def export_ioc(self, filepath: str) -> None:
        """Exports findings to a JSON file."""
        data = [f.to_dict() for f in self.findings]
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=4)
            print(f"{Colors.OKGREEN}Exported IoCs to {filepath}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Error exporting IoCs: {e}{Colors.ENDC}")

    def fix_issues(self, auto: bool = False) -> None:
        """Attempts to remediate issues."""
        if not self.findings:
            print("No findings to remediate.")
            return

        for finding in self.findings:
            if not finding.remediation:
                continue

            print(f"\n{Colors.WARNING}Finding: {finding.description}{Colors.ENDC}")
            print(f"Details: {finding.details}")
            print(f"Proposed Remediation: {finding.remediation}")
            
            if not auto:
                resp = input("Apply remediation? (y/N): ").lower()
                if resp != 'y':
                    print("Skipping.")
                    continue

            # Very basic remediation application
            try:
                if finding.remediation.startswith("chmod -s"):
                    filepath = finding.remediation.split(" ", 2)[2]
                    os.chmod(filepath, stat.S_IMODE(os.stat(filepath).st_mode) & ~stat.S_ISUID & ~stat.S_ISGID)
                    print(f"{Colors.OKGREEN}Successfully applied: {finding.remediation}{Colors.ENDC}")
                elif finding.remediation.startswith("kill -9"):
                    pid = finding.remediation.split(" ")[2]
                    os.kill(int(pid), 9)
                    print(f"{Colors.OKGREEN}Successfully applied: {finding.remediation}{Colors.ENDC}")
                else:
                    print(f"Manual remediation required: {finding.remediation}")
            except Exception as e:
                print(f"{Colors.FAIL}Failed to apply remediation: {e}{Colors.ENDC}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Persistence Hunter - Linux CTF Blue Team Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    parser_scan = subparsers.add_parser("scan", help="Run full system scan")
    
    # fix
    parser_fix = subparsers.add_parser("fix", help="Remediate found issues")
    parser_fix.add_argument("--auto", action="store_true", help="Automatically apply safe remediations")

    # watch
    parser_watch = subparsers.add_parser("watch", help="Continuous monitoring")
    parser_watch.add_argument("--interval", type=int, default=60, help="Scan interval in seconds")

    # ioc-export
    parser_ioc = subparsers.add_parser("ioc-export", help="Export findings as IoC JSON")
    parser_ioc.add_argument("file", type=str, help="Output JSON file path")

    args = parser.parse_args()

    # Must be root for many scans
    if os.geteuid() != 0:
        print(f"{Colors.WARNING}Warning: Not running as root. Some scans may fail or be incomplete.{Colors.ENDC}")

    hunter = PersistenceHunter()

    if args.command == "scan":
        print(f"{Colors.OKCYAN}Starting full system scan...{Colors.ENDC}\n")
        hunter.run_all_scans()
        hunter.print_findings()
        
    elif args.command == "fix":
        hunter.run_all_scans()
        hunter.fix_issues(auto=args.auto)
        
    elif args.command == "watch":
        print(f"{Colors.OKCYAN}Starting continuous monitoring (interval: {args.interval}s)...{Colors.ENDC}")
        try:
            while True:
                print(f"\n[{datetime.now().isoformat()}] Running scan...")
                hunter.run_all_scans()
                if hunter.findings:
                    hunter.print_findings()
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped.")
            
    elif args.command == "ioc-export":
        hunter.run_all_scans()
        hunter.export_ioc(args.file)
        
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
