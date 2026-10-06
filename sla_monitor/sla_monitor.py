#!/usr/bin/env python3
"""
SLA Monitor - CTF Blue Team Service Reliability and Uptime Tool.
Monitors, auto-recovers, and reports on the SLA of critical services.
"""

import argparse
import socket
import urllib.request
import urllib.error
import subprocess
import time
import datetime
import os
import json
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple

class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

@dataclass
class ServiceConfig:
    name: str
    unit_name: str
    ports: List[int]
    health_url: Optional[str]
    config_path: Optional[str]
    log_path: Optional[str]

# Global Service Registry
SERVICES = [
    ServiceConfig('nginx', 'nginx', [80, 443], 'http://localhost', '/etc/nginx/nginx.conf', '/var/log/nginx/access.log'),
    ServiceConfig('apache2', 'apache2', [80, 443], 'http://localhost', '/etc/apache2/apache2.conf', '/var/log/apache2/access.log'),
    ServiceConfig('mysql', 'mysql', [3306], None, '/etc/mysql/my.cnf', '/var/log/mysql/error.log'),
    ServiceConfig('mariadb', 'mariadb', [3306], None, '/etc/mysql/mariadb.cnf', '/var/log/mysql/error.log'),
    ServiceConfig('postgresql', 'postgresql', [5432], None, '/etc/postgresql/', '/var/log/postgresql/'),
    ServiceConfig('ssh', 'ssh', [22], None, '/etc/ssh/sshd_config', '/var/log/auth.log'),
    ServiceConfig('roundcube', 'apache2', [80], 'http://localhost/roundcube', '/etc/roundcube/config.inc.php', '/var/log/roundcube/'),
    ServiceConfig('gitlab', 'gitlab-runsvdir', [80, 443, 22], 'http://localhost', '/etc/gitlab/gitlab.rb', '/var/log/gitlab/'),
    ServiceConfig('elasticsearch', 'elasticsearch', [9200], 'http://localhost:9200', '/etc/elasticsearch/elasticsearch.yml', '/var/log/elasticsearch/'),
    ServiceConfig('kibana', 'kibana', [5601], 'http://localhost:5601', '/etc/kibana/kibana.yml', '/var/log/kibana/'),
    ServiceConfig('logstash', 'logstash', [5044], None, '/etc/logstash/logstash.yml', '/var/log/logstash/'),
    ServiceConfig('filebeat', 'filebeat', [], None, '/etc/filebeat/filebeat.yml', '/var/log/filebeat/'),
    ServiceConfig('splunk', 'splunk', [8000], 'http://localhost:8000', '/opt/splunk/etc/system/local/', '/opt/splunk/var/log/splunk/'),
    ServiceConfig('redis', 'redis-server', [6379], None, '/etc/redis/redis.conf', '/var/log/redis/redis-server.log'),
    ServiceConfig('mongodb', 'mongod', [27017], None, '/etc/mongod.conf', '/var/log/mongodb/mongod.log'),
    ServiceConfig('fail2ban', 'fail2ban', [], None, '/etc/fail2ban/jail.local', '/var/log/fail2ban.log'),
    ServiceConfig('auditd', 'auditd', [], None, '/etc/audit/auditd.conf', '/var/log/audit/audit.log'),
    ServiceConfig('rsyslog', 'rsyslog', [514], None, '/etc/rsyslog.conf', '/var/log/syslog'),
]

def is_process_running(unit_name: str) -> bool:
    """Check if a systemd unit is active."""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', unit_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip() == 'active'
    except Exception:
        return False

def check_ports(ports: List[int]) -> bool:
    """Check if all specified ports are open on localhost."""
    if not ports:
        return True # If no ports to check, assume open
    
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex(('127.0.0.1', port)) != 0:
                return False
    return True

def check_http(url: Optional[str]) -> Tuple[bool, bool]:
    """
    Check HTTP health endpoint.
    Returns: (is_reachable, is_200)
    """
    if not url:
        return True, True
    
    try:
        req = urllib.request.Request(url, method='GET')
        with urllib.request.urlopen(req, timeout=2.0) as response:
            return True, response.getcode() == 200
    except urllib.error.HTTPError as e:
        return True, False
    except Exception:
        return False, False

def determine_status(service: ServiceConfig) -> str:
    """
    Determine the status of a service based on SLA rules.
    - port open + (HTTP 200 if URL defined) = Active
    - port open + HTTP non-200 = Degraded
    - port closed + process running = Vulnerable
    - nothing = Down
    """
    running = is_process_running(service.unit_name)
    ports_open = check_ports(service.ports)
    
    # If service has no ports to check (like fail2ban), rely on process running
    if not service.ports:
        return 'Active' if running else 'Down'
    
    # If ports are closed but process is running
    if not ports_open and running:
        return 'Vulnerable'
    
    if ports_open:
        if service.health_url:
            reachable, is_200 = check_http(service.health_url)
            if is_200:
                return 'Active'
            else:
                return 'Degraded'
        else:
            return 'Active'
            
    return 'Down'

def colorize_status(status: str) -> str:
    if status == 'Active':
        return f"{Colors.GREEN}{status}{Colors.RESET}"
    elif status == 'Degraded':
        return f"{Colors.YELLOW}{status}{Colors.RESET}"
    elif status == 'Vulnerable':
        return f"{Colors.BLUE}{status}{Colors.RESET}"
    else:
        return f"{Colors.RED}{status}{Colors.RESET}"

def run_check():
    """Poll all registered services and print a colored status table."""
    print(f"{'Service':<20} | {'Status':<15} | {'Unit':<18} | {'Ports':<10}")
    print("-" * 68)
    for svc in SERVICES:
        status = determine_status(svc)
        ports_str = ",".join(map(str, svc.ports)) if svc.ports else "None"
        print(f"{svc.name:<20} | {colorize_status(status):<24} | {svc.unit_name:<18} | {ports_str:<10}")

def log_event(service_name: str, action: str, status: str):
    """Log events for the SLA report."""
    log_file = "/tmp/sla_monitor_watch.log"
    timestamp = datetime.datetime.now().isoformat()
    entry = {"timestamp": timestamp, "service": service_name, "action": action, "status": status}
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"Error logging event: {e}")

def run_watch(interval: int):
    """Continuous loop: on failure, auto-attempt systemctl restart, log each attempt."""
    print(f"Starting SLA watch mode. Polling every {interval} seconds...")
    try:
        while True:
            for svc in SERVICES:
                status = determine_status(svc)
                if status in ['Down', 'Degraded', 'Vulnerable']:
                    print(f"[{datetime.datetime.now().isoformat()}] {svc.name} is {status}. Attempting restart...")
                    log_event(svc.name, "Detected failure", status)
                    
                    try:
                        subprocess.run(
                            ['systemctl', 'restart', svc.unit_name],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=5
                        )
                        log_event(svc.name, "systemctl restart", "Attempted")
                    except Exception as e:
                        print(f"Failed to restart {svc.unit_name}: {e}")
                        log_event(svc.name, "systemctl restart", f"Failed: {e}")
                        
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nExiting watch mode.")

def run_harden():
    """Print a hardening checklist per service."""
    for svc in SERVICES:
        print(f"[{Colors.GREEN}{svc.name.upper()}{Colors.RESET}] Hardening Checklist:")
        if svc.config_path:
            print(f"  - Lock down configuration permissions: `chmod 640 {svc.config_path}` and `chown root:root {svc.config_path}`")
        if svc.log_path:
            print(f"  - Ensure log files are restricted: `chmod 640 {svc.log_path}`")
        if svc.ports:
            print(f"  - Verify firewall rules (iptables/ufw) allow only necessary traffic on ports: {','.join(map(str, svc.ports))}")
        
        # Specific service hardening suggestions
        if svc.name in ['nginx', 'apache2']:
            print("  - Disable server tokens/signatures in configuration.")
            print("  - Disable directory listing (Options -Indexes).")
        elif svc.name == 'ssh':
            print("  - Disable RootLogin (PermitRootLogin no).")
            print("  - Disable PasswordAuthentication if using keys.")
            print("  - Set AllowUsers to restrict SSH access.")
        elif svc.name in ['mysql', 'mariadb', 'postgresql']:
            print("  - Ensure database is bound to localhost (127.0.0.1) if not accessed externally.")
            print("  - Run mysql_secure_installation (for MySQL/MariaDB).")
        print()

def run_report():
    """Generate a markdown SLA uptime report from the watch log."""
    log_file = "/tmp/sla_monitor_watch.log"
    if not os.path.exists(log_file):
        print("No watch log found. Run 'watch' mode first to generate data.")
        return

    events = []
    try:
        with open(log_file, "r") as f:
            for line in f:
                events.append(json.loads(line.strip()))
    except Exception as e:
        print(f"Failed to read log file: {e}")
        return

    report = "# SLA Monitor Incident Report\n\n"
    report += f"**Generated At:** {datetime.datetime.now().isoformat()}\n\n"
    report += "## Incident Log\n\n"
    report += "| Timestamp | Service | Action | Status |\n"
    report += "|-----------|---------|--------|--------|\n"
    
    for event in events:
        report += f"| {event.get('timestamp')} | {event.get('service')} | {event.get('action')} | {event.get('status')} |\n"

    report_path = "sla_report.md"
    try:
        with open(report_path, "w") as f:
            f.write(report)
        print(f"SLA Report successfully generated at {os.path.abspath(report_path)}")
    except Exception as e:
        print(f"Failed to write report: {e}")

def main():
    parser = argparse.ArgumentParser(description="SLA Monitor - CTF Blue Team Service Tool")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Command to run")

    # Check
    check_parser = subparsers.add_parser("check", help="Poll all registered services and print status table")
    
    # Watch
    watch_parser = subparsers.add_parser("watch", help="Continuous loop to auto-restart failed services")
    watch_parser.add_argument("--interval", type=int, default=10, help="Polling interval in seconds (default: 10)")
    
    # Harden
    harden_parser = subparsers.add_parser("harden", help="Print hardening checklists per service")
    
    # Report
    report_parser = subparsers.add_parser("report", help="Generate a markdown SLA uptime report")

    args = parser.parse_args()

    if args.command == "check":
        run_check()
    elif args.command == "watch":
        run_watch(args.interval)
    elif args.command == "harden":
        run_harden()
    elif args.command == "report":
        run_report()

if __name__ == "__main__":
    main()
