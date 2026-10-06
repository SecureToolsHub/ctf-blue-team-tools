#!/usr/bin/env python3
"""
Web Configuration Auditor - Blue Team Security Tool
Audits web application and database configurations on local infrastructure.
Reads config files only, no network calls.
"""

import argparse
import dataclasses
from dataclasses import dataclass
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from typing import List, Dict, Optional, Any

# ==========================================
# CONSTANTS & CONFIGURATION
# ==========================================

class Colors:
    CRITICAL = '\033[91m' # Red
    HIGH = '\033[93m'     # Yellow
    MEDIUM = '\033[95m'   # Magenta
    LOW = '\033[94m'      # Blue
    RESET = '\033[0m'     # Reset

SEVERITY_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "all": 0}

@dataclass
class Finding:
    severity: str
    title: str
    file_path: str
    line: int
    current_value: str
    fix_instruction: str
    impact: str
    command: str

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

# ==========================================
# UTILITY FUNCTIONS
# ==========================================

def get_color(severity: str) -> str:
    return getattr(Colors, severity.upper(), Colors.RESET)

def format_finding_text(finding: Finding) -> str:
    color = get_color(finding.severity)
    return (f"{color}[{finding.severity.upper()}] {finding.title}{Colors.RESET}\n"
            f"  File: {finding.file_path}:{finding.line}\n"
            f"  Current: {finding.current_value}\n"
            f"  Fix: {finding.fix_instruction}\n"
            f"  Impact: {finding.impact}\n"
            f"  Command: {finding.command}\n")

def read_file_lines(filepath: str) -> List[str]:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()
    except Exception:
        return []

def search_files(file_patterns: List[str]) -> List[str]:
    files = []
    for pattern in file_patterns:
        files.extend(glob.glob(pattern, recursive=True))
    return [f for f in set(files) if os.path.isfile(f)]

def execute_fix(finding: Finding, dry_run: bool = False):
    print(f"Applying fix: {finding.title}")
    if dry_run:
        print(f"[DRY-RUN] Would run: {finding.command}")
        return

    # Backup file
    backup_path = f"{finding.file_path}.bak.{int(time.time())}"
    try:
        shutil.copy2(finding.file_path, backup_path)
        print(f"Backup created at: {backup_path}")
    except Exception as e:
        print(f"Error creating backup for {finding.file_path}: {e}")
        return

    # Execute sed command or equivalent
    try:
        result = subprocess.run(finding.command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Successfully applied fix to {finding.file_path}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to apply fix. Error: {e.stderr.decode()}")

# ==========================================
# AUDITORS
# ==========================================

def audit_nginx() -> List[Finding]:
    findings = []
    config_paths = ['/etc/nginx/nginx.conf', '/etc/nginx/sites-enabled/*', '/etc/nginx/conf.d/*']
    files = search_files(config_paths)

    for filepath in files:
        lines = read_file_lines(filepath)
        for i, line in enumerate(lines, 1):
            if re.search(r'^\s*server_tokens\s+on\s*;', line):
                findings.append(Finding(
                    severity='high', title='Nginx server_tokens exposed', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set server_tokens off;', impact='Exposes Nginx version, facilitating targeted exploits.',
                    command=f"sed -i 's/server_tokens\\s*on/server_tokens off/' {filepath}"
                ))
            if re.search(r'^\s*autoindex\s+on\s*;', line):
                findings.append(Finding(
                    severity='critical', title='Nginx Directory listing enabled', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set autoindex off;', impact='Exposes sensitive files and source code.',
                    command=f"sed -i 's/autoindex\\s*on/autoindex off/' {filepath}"
                ))
    return findings

def audit_php() -> List[Finding]:
    findings = []
    config_paths = ['/etc/php/*/cli/php.ini', '/etc/php/*/fpm/php.ini', '/etc/php/*/apache2/php.ini']
    files = search_files(config_paths)

    for filepath in files:
        lines = read_file_lines(filepath)
        for i, line in enumerate(lines, 1):
            if re.search(r'^\s*expose_php\s*=\s*On', line, re.IGNORECASE):
                findings.append(Finding(
                    severity='medium', title='PHP expose_php = On', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set expose_php = Off', impact='Leaks PHP version via X-Powered-By header.',
                    command=f"sed -i 's/^expose_php\\s*=.*/expose_php = Off/' {filepath}"
                ))
            if re.search(r'^\s*display_errors\s*=\s*On', line, re.IGNORECASE):
                findings.append(Finding(
                    severity='critical', title='PHP display_errors = On', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set display_errors = Off', impact='Exposes internal paths and error details; used in Roundcube RCE.',
                    command=f"sed -i 's/^display_errors\\s*=.*/display_errors = Off/' {filepath}"
                ))
            if re.search(r'^\s*allow_url_include\s*=\s*On', line, re.IGNORECASE):
                findings.append(Finding(
                    severity='critical', title='PHP allow_url_include = On', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set allow_url_include = Off', impact='Creates severe Remote File Inclusion (RFI) vectors.',
                    command=f"sed -i 's/^allow_url_include\\s*=.*/allow_url_include = Off/' {filepath}"
                ))
    return findings

def audit_roundcube() -> List[Finding]:
    findings = []
    config_paths = ['/var/www/html/roundcube/config/config.inc.php', '/etc/roundcube/config.inc.php']
    files = search_files(config_paths)

    for filepath in files:
        lines = read_file_lines(filepath)
        for i, line in enumerate(lines, 1):
            if re.search(r'\$config\[\'des_key\'\]\s*=\s*\'rcmExampleKey!!Devel\';', line):
                findings.append(Finding(
                    severity='critical', title='Roundcube default des_key', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Generate and set a random 24-character des_key', impact='Allows attackers to decrypt session cookies or sensitive data.',
                    command=f"sed -i \"s/'rcmExampleKey!!Devel'/'$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 24 | head -n 1)'/\" {filepath}"
                ))
            if re.search(r'\$config\[\'enable_installer\'\]\s*=\s*true;', line, re.IGNORECASE):
                findings.append(Finding(
                    severity='critical', title='Roundcube enable_installer set to true', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set enable_installer = false', impact='Allows attackers to reconfigure the webmail and gain RCE.',
                    command=f"sed -i 's/enable_installer.*true/enable_installer = false/' {filepath}"
                ))
    return findings

def audit_gitlab() -> List[Finding]:
    findings = []
    config_paths = ['/etc/gitlab/gitlab.rb']
    files = search_files(config_paths)

    for filepath in files:
        lines = read_file_lines(filepath)
        for i, line in enumerate(lines, 1):
            if re.search(r'^\s*external_url\s+[\'"]http://', line):
                findings.append(Finding(
                    severity='high', title='GitLab external_url uses HTTP', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Change external_url to use HTTPS', impact='Credentials and code transmitted in plaintext.',
                    command=f"sed -i 's/http:\\/\\//https:\\/\\//' {filepath}"
                ))
    return findings

def audit_mysql() -> List[Finding]:
    findings = []
    config_paths = ['/etc/mysql/my.cnf', '/etc/mysql/mysql.conf.d/mysqld.cnf', '/etc/mysql/mariadb.conf.d/50-server.cnf']
    files = search_files(config_paths)

    for filepath in files:
        lines = read_file_lines(filepath)
        for i, line in enumerate(lines, 1):
            if re.search(r'^\s*bind-address\s*=\s*0\.0\.0\.0', line):
                findings.append(Finding(
                    severity='critical', title='MySQL exposed externally (0.0.0.0)', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set bind-address = 127.0.0.1', impact='Allows remote brute-force or exploitation.',
                    command=f"sed -i 's/bind-address\\s*=\\s*0.0.0.0/bind-address = 127.0.0.1/' {filepath}"
                ))
            if re.search(r'^\s*local_infile\s*=\s*(ON|1)', line, re.IGNORECASE):
                findings.append(Finding(
                    severity='high', title='MySQL local_infile enabled', file_path=filepath, line=i, current_value=line.strip(),
                    fix_instruction='Set local_infile = OFF', impact='Allows arbitrary file reading via malicious SQL clients.',
                    command=f"sed -i 's/local_infile\\s*=.*/local_infile = OFF/' {filepath}"
                ))
    return findings

def audit_postgresql() -> List[Finding]:
    findings = []
    files = search_files(['/etc/postgresql/*/main/pg_hba.conf', '/etc/postgresql/*/main/postgresql.conf'])

    for filepath in files:
        lines = read_file_lines(filepath)
        if 'pg_hba.conf' in filepath:
            for i, line in enumerate(lines, 1):
                if line.strip().startswith('#'): continue
                if 'trust' in line:
                    findings.append(Finding(
                        severity='critical', title='PostgreSQL trust authentication used', file_path=filepath, line=i, current_value=line.strip(),
                        fix_instruction='Change trust to md5 or scram-sha-256', impact='Allows login without password.',
                        command=f"sed -i '{i}s/trust/md5/' {filepath}"
                    ))
        elif 'postgresql.conf' in filepath:
            for i, line in enumerate(lines, 1):
                if re.search(r'^\s*listen_addresses\s*=\s*\'\*\'', line):
                    findings.append(Finding(
                        severity='critical', title='PostgreSQL listens on all interfaces', file_path=filepath, line=i, current_value=line.strip(),
                        fix_instruction="Set listen_addresses = 'localhost'", impact='Database exposed to network.',
                        command=f"sed -i \"s/listen_addresses\\s*=\\s*'*'/listen_addresses = 'localhost'/\" {filepath}"
                    ))
    return findings

def webshell_scan(webroot: str) -> List[Finding]:
    findings = []
    suspicious_patterns = [
        r'eval\s*\(\s*base64_decode',
        r'system\s*\(',
        r'exec\s*\(',
        r'passthru\s*\(',
        r'shell_exec\s*\(',
        r'preg_replace\s*\(\s*["\'].*e["\']'
    ]
    
    if not os.path.isdir(webroot):
        return findings

    for root, _, files in os.walk(webroot):
        for file in files:
            if not file.endswith('.php'): continue
            filepath = os.path.join(root, file)
            
            # Read content
            lines = read_file_lines(filepath)
            for i, line in enumerate(lines, 1):
                for pattern in suspicious_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        mtime = datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                        findings.append(Finding(
                            severity='critical',
                            title=f'Suspicious PHP function detected ({pattern})',
                            file_path=filepath,
                            line=i,
                            current_value=f"ModTime: {mtime} | Snippet: {line.strip()[:200]}",
                            fix_instruction='Review file manually. Remove if unauthorized.',
                            impact='Potential webshell allowing RCE.',
                            command=f"mv {filepath} {filepath}.quarantine"
                        ))
                        break # Prevent multiple findings per line
    return findings


# ==========================================
# MAIN EXECUTION
# ==========================================

def get_auditors(services: str) -> Dict[str, callable]:
    service_list = [s.strip().lower() for s in services.split(',')]
    all_auditors = {
        'nginx': audit_nginx,
        'php': audit_php,
        'roundcube': audit_roundcube,
        'gitlab': audit_gitlab,
        'mysql': audit_mysql,
        'postgresql': audit_postgresql,
    }
    
    if 'all' in service_list:
        return all_auditors
    
    return {k: v for k, v in all_auditors.items() if k in service_list}

def output_findings(findings: List[Finding], format: str, severity: str, output_file: Optional[str]):
    min_level = SEVERITY_LEVELS.get(severity.lower(), 0)
    filtered = [f for f in findings if SEVERITY_LEVELS.get(f.severity, 0) >= min_level]
    
    if format == 'text':
        out = "\n".join(format_finding_text(f) for f in filtered)
    elif format == 'json':
        out = json.dumps([f.to_dict() for f in filtered], indent=2)
    elif format == 'markdown':
        out = "# Configuration Audit Findings\n\n"
        for f in filtered:
            out += f"## {f.title} ({f.severity.upper()})\n"
            out += f"- **File**: `{f.file_path}:{f.line}`\n"
            out += f"- **Current**: `{f.current_value}`\n"
            out += f"- **Fix**: {f.fix_instruction}\n"
            out += f"- **Impact**: {f.impact}\n"
            out += f"- **Command**: `{f.command}`\n\n"
    
    if output_file:
        with open(output_file, 'w') as f:
            f.write(out)
        print(f"Report written to {output_file}")
    else:
        print(out)

def main():
    parser = argparse.ArgumentParser(description="Web Configuration Auditor")
    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # Audit subcommand
    audit_parser = subparsers.add_parser('audit', help='Audit services')
    audit_parser.add_argument('--services', default='all', help='Comma-separated list of services')
    audit_parser.add_argument('--severity', default='all', choices=SEVERITY_LEVELS.keys())
    audit_parser.add_argument('--format', default='text', choices=['text', 'json', 'markdown'])
    audit_parser.add_argument('--output', help='Output file path')

    # Individual service audit subcommands
    for svc in ['nginx', 'php', 'roundcube', 'gitlab', 'mysql', 'postgresql']:
        subparsers.add_parser(f'audit-{svc}', help=f'Audit {svc.title()} configuration')

    # Webshell scan
    webshell_parser = subparsers.add_parser('webshell-scan', help='Scan web roots for suspicious PHP files')
    webshell_parser.add_argument('--webroot', default='/var/www', help='Web root directory')

    # Fix subcommand
    fix_parser = subparsers.add_parser('fix', help='Apply configuration fixes')
    fix_parser.add_argument('--check', required=True, help='Fix a specific check by title/name')
    fix_parser.add_argument('--dry-run', action='store_true', help='Show what would change')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    all_findings = []

    if args.command == 'audit':
        auditors = get_auditors(args.services)
        for name, auditor in auditors.items():
            all_findings.extend(auditor())
        output_findings(all_findings, args.format, args.severity, args.output)

    elif args.command.startswith('audit-'):
        service = args.command.split('-')[1]
        auditors = get_auditors(service)
        for name, auditor in auditors.items():
            all_findings.extend(auditor())
        output_findings(all_findings, 'text', 'all', None)

    elif args.command == 'webshell-scan':
        findings = webshell_scan(args.webroot)
        output_findings(findings, 'text', 'all', None)

    elif args.command == 'fix':
        # Re-run all audits to find the check by name
        auditors = get_auditors('all')
        for name, auditor in auditors.items():
            all_findings.extend(auditor())
        
        target_findings = [f for f in all_findings if args.check.lower() in f.title.lower()]
        if not target_findings:
            print(f"No finding matching '{args.check}' found.")
            sys.exit(1)
            
        for finding in target_findings:
            execute_fix(finding, args.dry_run)

if __name__ == "__main__":
    main()
