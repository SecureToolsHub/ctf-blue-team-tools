#!/usr/bin/env python3
"""
vuln_patcher.py — Automated vulnerability patcher for Blue Team CTF

Capabilities:
1. `audit` — Run a comprehensive audit and list all vulnerabilities found with severity
2. `patch` — Apply a specific patch by name
3. `patch-all` — Apply all auto-patchable fixes (with --dry-run option)
4. `verify` — Verify a specific patch was applied correctly
"""

import os
import sys
import shutil
import datetime
import argparse
import subprocess
from pathlib import Path

# Colors
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

def log(msg: str, level: str = "INFO"):
    color = Colors.ENDC
    if level == "INFO": color = Colors.OKBLUE
    elif level == "SUCCESS": color = Colors.OKGREEN
    elif level == "WARNING": color = Colors.WARNING
    elif level == "ERROR": color = Colors.FAIL
    print(f"{color}[{level}] {msg}{Colors.ENDC}")

def backup_file(filepath: str) -> str:
    """Create a backup before modifying."""
    if not os.path.exists(filepath):
        return ""
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = f"{filepath}.bak.{timestamp}"
    shutil.copy2(filepath, backup_path)
    log(f"Backed up {filepath} to {backup_path}", "INFO")
    return backup_path

def run_cmd(cmd: str, check=False) -> subprocess.CompletedProcess:
    """Helper to run a shell command."""
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)

class Patcher:
    """Base class for patchers."""
    name = "base"
    severity = "LOW"
    description = "Base patcher"

    def audit(self) -> bool:
        """Return True if vulnerability is present."""
        return False

    def patch(self, dry_run: bool = False) -> bool:
        """Apply patch. Return True if successful."""
        return False

    def verify(self) -> bool:
        """Return True if patch is applied correctly."""
        return not self.audit()

class SuidSgidPatcher(Patcher):
    name = "suid_sgid"
    severity = "HIGH"
    description = "Detect and patch non-standard SUID binaries"
    
    known_good_suid = ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/su", "/usr/bin/newgrp", "/usr/bin/chfn", "/usr/bin/gpasswd", "/bin/umount", "/bin/mount", "/usr/bin/umount", "/usr/bin/mount", "/bin/su", "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"]

    def __init__(self):
        self.found_bad = []

    def audit(self):
        self.found_bad = []
        try:
            out = run_cmd("find /usr/bin /bin /usr/local/bin /opt -type f -perm -4000 2>/dev/null").stdout.splitlines()
            for binary in out:
                if binary not in self.known_good_suid:
                    self.found_bad.append(binary)
        except Exception:
            pass
        return len(self.found_bad) > 0

    def patch(self, dry_run=False):
        if not self.found_bad:
            self.audit()
        if not self.found_bad:
            log("No suspicious SUID binaries found.", "SUCCESS")
            return True
        for binary in self.found_bad:
            log(f"Suspicious SUID binary found: {binary}", "WARNING")
            if dry_run:
                log(f"[DRY-RUN] Would run: chmod u-s {binary}", "INFO")
            else:
                backup_file(binary)
                run_cmd(f"chmod u-s {binary}")
                log(f"Removed SUID bit from {binary}", "SUCCESS")
        return True

class CronPersistencePatcher(Patcher):
    name = "cron_persistence"
    severity = "HIGH"
    description = "Detect and remove suspicious cron entries"

    def __init__(self):
        self.suspicious = []

    def audit(self):
        self.suspicious = []
        out = run_cmd("grep -R -E 'bash -i|/dev/tcp|nc -e|curl|wget' /etc/crontab /etc/cron.* /var/spool/cron/crontabs 2>/dev/null").stdout.splitlines()
        for line in out:
            self.suspicious.append(line)
        return len(self.suspicious) > 0

    def patch(self, dry_run=False):
        if not self.suspicious:
            self.audit()
        if not self.suspicious:
            log("No suspicious cron jobs found.", "SUCCESS")
            return True
        for line in self.suspicious:
            log(f"Suspicious cron: {line}", "WARNING")
            if dry_run:
                log(f"[DRY-RUN] Would remove cron entry containing: {line}", "INFO")
            else:
                log(f"Please manually remove this entry. Automated removal is risky.", "WARNING")
        return True

class SystemdBackdoorPatcher(Patcher):
    name = "systemd_backdoor"
    severity = "HIGH"
    description = "Detect and remove suspicious systemd unit files"
    
    def __init__(self):
        self.suspicious = []

    def audit(self):
        self.suspicious = []
        out = run_cmd("grep -R -l -E 'bash -i|/dev/tcp|nc -e' /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null").stdout.splitlines()
        for unit in out:
            self.suspicious.append(unit)
        return len(self.suspicious) > 0

    def patch(self, dry_run=False):
        if not self.suspicious:
            self.audit()
        if not self.suspicious:
            log("No suspicious systemd units found.", "SUCCESS")
            return True
        for unit in self.suspicious:
            log(f"Suspicious systemd unit: {unit}", "WARNING")
            if dry_run:
                log(f"[DRY-RUN] Would disable, mask, and delete {unit}", "INFO")
            else:
                unit_name = os.path.basename(unit)
                run_cmd(f"systemctl stop {unit_name}")
                run_cmd(f"systemctl disable {unit_name}")
                run_cmd(f"systemctl mask {unit_name}")
                backup_file(unit)
                os.remove(unit)
                run_cmd("systemctl daemon-reload")
                log(f"Removed and masked systemd unit {unit}", "SUCCESS")
        return True

class WeakSshConfigPatcher(Patcher):
    name = "weak_ssh_config"
    severity = "MEDIUM"
    description = "Detect and patch weak SSH configurations"

    def audit(self):
        out = run_cmd("grep -E '^PermitRootLogin yes|^PasswordAuthentication yes|^PermitEmptyPasswords yes' /etc/ssh/sshd_config").stdout
        return bool(out.strip())

    def patch(self, dry_run=False):
        if not self.audit():
            log("SSH config looks secure.", "SUCCESS")
            return True
        
        filepath = "/etc/ssh/sshd_config"
        if dry_run:
            log(f"[DRY-RUN] Would apply secure defaults to {filepath}", "INFO")
            return True
            
        backup_file(filepath)
        run_cmd("sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config")
        run_cmd("sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config")
        run_cmd("sed -i 's/^PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config")
        run_cmd("systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null")
        log("Secured SSH config and restarted sshd", "SUCCESS")
        return True

class WorldWritablePatcher(Patcher):
    name = "world_writable"
    severity = "MEDIUM"
    description = "Detect and patch world-writable sensitive files in /etc"

    def __init__(self):
        self.files = []

    def audit(self):
        self.files = run_cmd("find /etc -type f -perm -0002 2>/dev/null").stdout.splitlines()
        return len(self.files) > 0

    def patch(self, dry_run=False):
        if not self.files:
            self.audit()
        if not self.files:
            log("No world-writable files found in /etc.", "SUCCESS")
            return True
            
        for f in self.files:
            log(f"World-writable file: {f}", "WARNING")
            if dry_run:
                log(f"[DRY-RUN] Would run chmod o-w {f}", "INFO")
            else:
                backup_file(f)
                run_cmd(f"chmod o-w {f}")
                log(f"Removed world-writable permission from {f}", "SUCCESS")
        return True

class SudoersNopasswdPatcher(Patcher):
    name = "sudoers_nopasswd"
    severity = "HIGH"
    description = "Detect overly permissive sudoers (NOPASSWD)"

    def audit(self):
        out = run_cmd("grep -R NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null").stdout.splitlines()
        for line in out:
            log(f"Sudoers NOPASSWD found: {line}", "WARNING")
        return len(out) > 0

    def patch(self, dry_run=False):
        log("Manual review required for sudoers. Will not auto-patch.", "WARNING")
        return True

class ListeningBackdoorPatcher(Patcher):
    name = "listening_backdoor"
    severity = "CRITICAL"
    description = "Detect unexpected listeners and patch"

    known_ports = ["22", "80", "443", "53"] # Example baseline

    def __init__(self):
        self.suspicious_pids = []

    def audit(self):
        out = run_cmd("ss -tlnp").stdout.splitlines()
        for line in out[1:]:
            parts = line.split()
            if len(parts) >= 6:
                port = parts[3].split(":")[-1]
                if port not in self.known_ports:
                    if "pid=" in parts[5]:
                        pid = parts[5].split("pid=")[1].split(",")[0]
                        self.suspicious_pids.append((port, pid))
        return len(self.suspicious_pids) > 0

    def patch(self, dry_run=False):
        if not self.suspicious_pids:
            self.audit()
        if not self.suspicious_pids:
            log("No suspicious listeners found.", "SUCCESS")
            return True
            
        for port, pid in self.suspicious_pids:
            log(f"Suspicious listener on port {port} (PID: {pid})", "WARNING")
            if dry_run:
                log(f"[DRY-RUN] Would kill PID {pid} and block port {port}", "INFO")
            else:
                run_cmd(f"kill -9 {pid}")
                run_cmd(f"iptables -A INPUT -p tcp --dport {port} -j DROP")
                log(f"Killed PID {pid} and blocked port {port}", "SUCCESS")
        return True

class FirewallGapsPatcher(Patcher):
    name = "firewall_gaps"
    severity = "MEDIUM"
    description = "Detect missing firewall rules and apply standard ruleset"

    def audit(self):
        out = run_cmd("ufw status").stdout
        return "inactive" in out.lower()

    def patch(self, dry_run=False):
        if not self.audit():
            log("Firewall appears active.", "SUCCESS")
            return True
            
        if dry_run:
            log("[DRY-RUN] Would enable UFW and apply standard rules", "INFO")
            return True
            
        run_cmd("ufw --force enable")
        run_cmd("ufw default deny incoming")
        run_cmd("ufw default allow outgoing")
        run_cmd("ufw allow ssh")
        log("Enabled UFW and applied standard ruleset", "SUCCESS")
        return True

class AppArmorSelinuxPatcher(Patcher):
    name = "apparmor_selinux"
    severity = "MEDIUM"
    description = "Check if AppArmor/SELinux is disabled and enforce"

    def audit(self):
        aa = run_cmd("aa-status").stdout
        se = run_cmd("sestatus").stdout
        return "disabled" in aa.lower() or "disabled" in se.lower()

    def patch(self, dry_run=False):
        if dry_run:
            log("[DRY-RUN] Would enforce AppArmor/SELinux", "INFO")
            return True
        log("Enforcing AppArmor/SELinux might require reboot or complex configuration. Please review manually.", "WARNING")
        return True

class GitlabHardeningPatcher(Patcher):
    name = "gitlab_hardening"
    severity = "HIGH"
    description = "Detect public GitLab API without auth"

    def audit(self):
        out = run_cmd("curl -s -o /dev/null -w '%{http_code}' http://localhost/api/v4/projects").stdout
        if out == "200":
            return True
        return False

    def patch(self, dry_run=False):
        if dry_run:
            log("[DRY-RUN] Would restrict GitLab API access", "INFO")
            return True
        log("Manual configuration of GitLab required.", "WARNING")
        return True

class RoundcubeHardeningPatcher(Patcher):
    name = "roundcube_hardening"
    severity = "HIGH"
    description = "Check for Roundcube vulnerabilities and webshells"

    def audit(self):
        out = run_cmd("find /var/www/html /var/www/roundcube -name '*.php' -type f -exec grep -lE 'system\\(|shell_exec\\(|passthru\\(' {} + 2>/dev/null").stdout.splitlines()
        for shell in out:
            log(f"Possible webshell found: {shell}", "WARNING")
        return len(out) > 0

    def patch(self, dry_run=False):
        if dry_run:
            log("[DRY-RUN] Would disable dangerous PHP functions and restrict permissions", "INFO")
            return True
        run_cmd("sed -i 's/^disable_functions =.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' /etc/php/*/apache2/php.ini")
        run_cmd("systemctl restart apache2")
        log("Disabled dangerous PHP functions", "SUCCESS")
        return True

PATCHERS = [
    SuidSgidPatcher(),
    CronPersistencePatcher(),
    SystemdBackdoorPatcher(),
    WeakSshConfigPatcher(),
    WorldWritablePatcher(),
    SudoersNopasswdPatcher(),
    ListeningBackdoorPatcher(),
    FirewallGapsPatcher(),
    AppArmorSelinuxPatcher(),
    GitlabHardeningPatcher(),
    RoundcubeHardeningPatcher()
]

def main():
    parser = argparse.ArgumentParser(description="Automated vulnerability patcher for Blue Team CTF.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # audit
    sub.add_parser("audit", help="Run comprehensive audit")

    # patch
    p_patch = sub.add_parser("patch", help="Apply a specific patch by name")
    p_patch.add_argument("name", help="Name of the patch to apply")
    p_patch.add_argument("--dry-run", action="store_true", help="Do not actually change files")

    # patch-all
    p_patch_all = sub.add_parser("patch-all", help="Apply all auto-patchable fixes")
    p_patch_all.add_argument("--dry-run", action="store_true", help="Do not actually change files")

    # verify
    p_verify = sub.add_parser("verify", help="Verify a specific patch was applied correctly")
    p_verify.add_argument("name", help="Name of the patch to verify")

    args = parser.parse_args()

    if args.cmd == "audit":
        log("Starting comprehensive audit...", "INFO")
        for p in PATCHERS:
            if p.audit():
                log(f"VULNERABILITY FOUND: {p.name} (Severity: {p.severity}) - {p.description}", "ERROR")
            else:
                log(f"OK: {p.name}", "SUCCESS")
                
    elif args.cmd == "patch":
        for p in PATCHERS:
            if p.name == args.name:
                p.patch(dry_run=args.dry_run)
                break
        else:
            log(f"Patch '{args.name}' not found.", "ERROR")
            
    elif args.cmd == "patch-all":
        log("Applying all patches...", "INFO")
        for p in PATCHERS:
            log(f"Running patcher: {p.name}", "INFO")
            p.patch(dry_run=args.dry_run)
            
    elif args.cmd == "verify":
        for p in PATCHERS:
            if p.name == args.name:
                if p.verify():
                    log(f"Patch {p.name} is verified (Issue not present).", "SUCCESS")
                else:
                    log(f"Patch {p.name} failed verification (Issue still present).", "ERROR")
                break
        else:
            log(f"Patch '{args.name}' not found.", "ERROR")

if __name__ == "__main__":
    if os.geteuid() != 0 and len(sys.argv) > 1 and sys.argv[1] not in ["audit", "verify"]:
        log("Warning: You are not running as root. Some patches may fail.", "WARNING")
    main()
