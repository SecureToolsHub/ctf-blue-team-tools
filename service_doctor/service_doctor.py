#!/usr/bin/env python3
"""
service_doctor.py — Blue Team CTF service restoration & triage tool.

For competitions where "critical services are not running" and you need
to diagnose and restore them quickly.

Capabilities:
  check    — Quick health check of common services + ports
  fix      — Attempt automated restart/repair of a named service
  scan     — Discover all listening ports and dead-but-installed services
  watch    — Monitor a service continuously (re-attempt restart on failure)
  checklist — Print a human checklist of common Blue Team service restoration steps

Usage:
    python3 service_doctor.py check
    python3 service_doctor.py check --services nginx,mysql,ssh,elasticsearch
    python3 service_doctor.py scan
    python3 service_doctor.py fix nginx
    python3 service_doctor.py fix elasticsearch --config /etc/elasticsearch/elasticsearch.yml
    python3 service_doctor.py watch splunk --interval 30
    python3 service_doctor.py checklist
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Known service profiles — name -> expected port(s) + common fix hints
# ---------------------------------------------------------------------------

SERVICE_PROFILES = {
    "nginx":            {"ports": [80, 443], "systemd": "nginx",
                         "config": "/etc/nginx/nginx.conf",
                         "log": "/var/log/nginx/error.log",
                         "test_cmd": "nginx -t"},
    "apache2":          {"ports": [80, 443], "systemd": "apache2",
                         "config": "/etc/apache2/apache2.conf",
                         "log": "/var/log/apache2/error.log",
                         "test_cmd": "apache2ctl configtest"},
    "apache":           {"ports": [80, 443], "systemd": "httpd",
                         "config": "/etc/httpd/conf/httpd.conf",
                         "log": "/var/log/httpd/error_log",
                         "test_cmd": "apachectl configtest"},
    "mysql":            {"ports": [3306], "systemd": "mysql",
                         "config": "/etc/mysql/my.cnf",
                         "log": "/var/log/mysql/error.log",
                         "test_cmd": None},
    "mariadb":          {"ports": [3306], "systemd": "mariadb",
                         "config": "/etc/mysql/mariadb.conf.d/50-server.cnf",
                         "log": "/var/log/mysql/error.log",
                         "test_cmd": None},
    "postgresql":       {"ports": [5432], "systemd": "postgresql",
                         "config": "/etc/postgresql",
                         "log": "/var/log/postgresql",
                         "test_cmd": None},
    "ssh":              {"ports": [22], "systemd": "ssh",
                         "config": "/etc/ssh/sshd_config",
                         "log": "/var/log/auth.log",
                         "test_cmd": "sshd -t"},
    "elasticsearch":    {"ports": [9200, 9300], "systemd": "elasticsearch",
                         "config": "/etc/elasticsearch/elasticsearch.yml",
                         "log": "/var/log/elasticsearch",
                         "test_cmd": None},
    "kibana":           {"ports": [5601], "systemd": "kibana",
                         "config": "/etc/kibana/kibana.yml",
                         "log": "/var/log/kibana",
                         "test_cmd": None},
    "logstash":         {"ports": [5044, 9600], "systemd": "logstash",
                         "config": "/etc/logstash/logstash.yml",
                         "log": "/var/log/logstash",
                         "test_cmd": None},
    "splunk":           {"ports": [8000, 8089, 9997], "systemd": None,
                         "config": "/opt/splunk/etc/system/local",
                         "log": "/opt/splunk/var/log/splunk",
                         "test_cmd": "/opt/splunk/bin/splunk status"},
    "redis":            {"ports": [6379], "systemd": "redis",
                         "config": "/etc/redis/redis.conf",
                         "log": "/var/log/redis/redis-server.log",
                         "test_cmd": None},
    "mongodb":          {"ports": [27017], "systemd": "mongod",
                         "config": "/etc/mongod.conf",
                         "log": "/var/log/mongodb/mongod.log",
                         "test_cmd": None},
    "rsyslog":          {"ports": [514], "systemd": "rsyslog",
                         "config": "/etc/rsyslog.conf",
                         "log": "/var/log/syslog",
                         "test_cmd": "rsyslogd -N1"},
    "filebeat":         {"ports": [], "systemd": "filebeat",
                         "config": "/etc/filebeat/filebeat.yml",
                         "log": "/var/log/filebeat/filebeat",
                         "test_cmd": "filebeat test config"},
    "winlogbeat":       {"ports": [], "systemd": "winlogbeat",
                         "config": "/etc/winlogbeat/winlogbeat.yml",
                         "log": None,
                         "test_cmd": "winlogbeat test config"},
    "metricbeat":       {"ports": [], "systemd": "metricbeat",
                         "config": "/etc/metricbeat/metricbeat.yml",
                         "log": None,
                         "test_cmd": "metricbeat test config"},
    "auditd":           {"ports": [], "systemd": "auditd",
                         "config": "/etc/audit/auditd.conf",
                         "log": "/var/log/audit/audit.log",
                         "test_cmd": None},
    "fail2ban":         {"ports": [], "systemd": "fail2ban",
                         "config": "/etc/fail2ban/jail.conf",
                         "log": "/var/log/fail2ban.log",
                         "test_cmd": "fail2ban-client status"},
    "ufw":              {"ports": [], "systemd": "ufw",
                         "config": "/etc/ufw",
                         "log": "/var/log/ufw.log",
                         "test_cmd": "ufw status"},
    "docker":           {"ports": [], "systemd": "docker",
                         "config": "/etc/docker/daemon.json",
                         "log": "/var/log/docker.log",
                         "test_cmd": "docker info"},
}

DEFAULT_CHECKS = [
    "nginx", "apache2", "ssh", "mysql", "postgresql",
    "elasticsearch", "kibana", "splunk", "filebeat",
    "rsyslog", "docker", "redis", "mongodb",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok(msg): print(f"  \033[92m[+]\033[0m {msg}")
def warn(msg): print(f"  \033[93m[!]\033[0m {msg}")
def fail(msg): print(f"  \033[91m[-]\033[0m {msg}")
def info(msg): print(f"  \033[94m[~]\033[0m {msg}")
def hdr(msg):  print(f"\n\033[1m{msg}\033[0m")


def systemctl(action, service):
    """Run systemctl <action> <service>. Returns (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            ["systemctl", action, service],
            capture_output=True, text=True, timeout=15
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except FileNotFoundError:
        return -1, "", "systemctl not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timed out"


def is_port_open(port, host="127.0.0.1", timeout=1.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def service_is_active(service_name):
    rc, stdout, _ = systemctl("is-active", service_name)
    return stdout == "active"


def get_service_status(service_name):
    rc, stdout, stderr = systemctl("status", service_name)
    return stdout or stderr


def list_failed_services():
    try:
        r = subprocess.run(
            ["systemctl", "--failed", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=10
        )
        return r.stdout.strip()
    except Exception:
        return ""


def tail_log(log_path, lines=20):
    if not log_path:
        return ""
    try:
        if os.path.isdir(log_path):
            # pick the most recently modified file
            files = [os.path.join(log_path, f) for f in os.listdir(log_path)
                     if os.path.isfile(os.path.join(log_path, f))]
            if not files:
                return ""
            log_path = max(files, key=os.path.getmtime)
        r = subprocess.run(
            ["tail", "-n", str(lines), log_path],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip()
    except Exception as e:
        return f"(could not read log: {e})"


def run_test_cmd(cmd):
    if not cmd:
        return None, None
    try:
        r = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=10)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_check(args):
    services = [s.strip() for s in args.services.split(",")] if args.services else DEFAULT_CHECKS

    hdr("═══ SERVICE HEALTH CHECK ═══")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = []
    for svc in services:
        profile = SERVICE_PROFILES.get(svc, {})
        systemd_name = profile.get("systemd", svc)
        ports = profile.get("ports", [])

        active = service_is_active(systemd_name) if systemd_name else None
        open_ports = [p for p in ports if is_port_open(p)]

        if active:
            status = "ACTIVE"
        elif active is False:
            status = "INACTIVE"
        else:
            status = "UNKNOWN"

        port_str = (
            "[" + ",".join(f"{p}:{'✓' if p in open_ports else '✗'}" for p in ports) + "]"
            if ports else "[no ports]"
        )

        line = f"  {svc:<20} {status:<10} {port_str}"
        if status == "ACTIVE" and (not ports or open_ports):
            ok(f"{svc:<20} {status:<10} {port_str}")
        elif status == "INACTIVE":
            fail(f"{svc:<20} {status:<10} {port_str}  ← RUN: service_doctor.py fix {svc}")
        else:
            warn(f"{svc:<20} {status:<10} {port_str}")

        results.append({"service": svc, "status": status, "ports": port_str})

    # Show globally failed services
    hdr("Systemd Failed Units:")
    failed = list_failed_services()
    if failed:
        for line in failed.splitlines():
            fail(line)
    else:
        ok("No failed systemd units detected")


def cmd_scan(args):
    hdr("═══ OPEN PORTS SCAN (localhost) ═══")
    RANGE_START, RANGE_END = 1, 10000
    info(f"Scanning ports {RANGE_START}-{RANGE_END} on 127.0.0.1 ...")

    open_ports = []
    for port in range(RANGE_START, RANGE_END + 1):
        if is_port_open(port, timeout=0.3):
            open_ports.append(port)

    if open_ports:
        ok(f"Open ports: {open_ports}")
        for port in open_ports:
            matched = [name for name, p in SERVICE_PROFILES.items()
                       if port in p.get("ports", [])]
            svc_str = f"  ← likely: {', '.join(matched)}" if matched else ""
            print(f"    :{port}{svc_str}")
    else:
        warn("No open ports found in range 1-10000")

    hdr("Systemd Failed Units:")
    print(list_failed_services() or "  (none)")

    hdr("Installed but disabled services:")
    try:
        r = subprocess.run(
            ["systemctl", "list-units", "--state=inactive", "--no-pager", "--plain"],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stdout.splitlines()[:30]:
            info(line)
    except Exception:
        warn("Could not enumerate inactive units")


def cmd_fix(args):
    svc = args.service.lower()
    profile = SERVICE_PROFILES.get(svc, {})
    systemd_name = profile.get("systemd", svc)
    config = args.config or profile.get("config")
    log_path = profile.get("log")
    test_cmd = profile.get("test_cmd")

    hdr(f"═══ FIX: {svc} ═══")
    info(f"Systemd unit : {systemd_name}")
    info(f"Config       : {config}")
    info(f"Log          : {log_path}")

    # 1. Config test
    if test_cmd:
        hdr("Step 1: Config syntax test")
        passed, output = run_test_cmd(test_cmd)
        if passed:
            ok(f"Config OK: {output[:200]}")
        else:
            fail(f"Config test FAILED:\n{output[:500]}")
            warn("Fix the config errors above before restarting.")
            if log_path:
                hdr("Last 20 log lines:")
                print(tail_log(log_path, 20))
            sys.exit(1)
    else:
        hdr("Step 1: Config test (no test command configured — skipping)")

    # 2. Enable + restart
    hdr("Step 2: Enable + restart service")
    rc, out, err = systemctl("enable", systemd_name)
    if rc == 0:
        ok(f"Enabled: {systemd_name}")
    else:
        warn(f"Enable returned {rc}: {err}")

    rc, out, err = systemctl("restart", systemd_name)
    if rc == 0:
        ok(f"Restarted: {systemd_name}")
    else:
        fail(f"Restart FAILED (rc={rc}): {err}")

    # 3. Verify active
    hdr("Step 3: Verify active")
    time.sleep(2)
    active = service_is_active(systemd_name)
    if active:
        ok(f"{svc} is now ACTIVE")
    else:
        fail(f"{svc} is still INACTIVE after restart")
        hdr("Systemd status:")
        print(get_service_status(systemd_name)[:600])

    # 4. Port check
    ports = profile.get("ports", [])
    if ports:
        hdr("Step 4: Port verification")
        for p in ports:
            if is_port_open(p):
                ok(f"Port {p} is OPEN")
            else:
                fail(f"Port {p} is CLOSED — service may still be starting up")

    # 5. Recent logs
    if log_path:
        hdr("Step 5: Recent log output (last 15 lines):")
        print(tail_log(log_path, 15))

    hdr("Quick-fix Tips")
    tips = {
        "elasticsearch": [
            "Check heap size: ES_JAVA_OPTS or jvm.options (min 1g for CTF)",
            "Check data dir permissions: chown -R elasticsearch:elasticsearch /var/lib/elasticsearch",
            "Check network.host in elasticsearch.yml — use 0.0.0.0 or specific IP",
            "Single-node: add 'discovery.type: single-node' to elasticsearch.yml",
        ],
        "kibana": [
            "Ensure elasticsearch.hosts URL is correct in kibana.yml",
            "Wait ~30s after Elasticsearch starts before starting Kibana",
        ],
        "nginx": [
            "Test config: nginx -t",
            "Check port 80/443 not occupied: ss -tlnp | grep ':80'",
        ],
        "mysql": [
            "Check data dir: ls -la /var/lib/mysql",
            "Check socket: mysqladmin -u root status",
            "Init if fresh: mysqld --initialize --user=mysql",
        ],
        "splunk": [
            "Start: /opt/splunk/bin/splunk start --accept-license",
            "Check: /opt/splunk/bin/splunk status",
        ],
    }
    for tip in tips.get(svc, ["No specific tips — check logs above."]):
        info(tip)


def cmd_watch(args):
    svc = args.service.lower()
    profile = SERVICE_PROFILES.get(svc, {})
    systemd_name = profile.get("systemd", svc)
    interval = args.interval
    max_attempts = args.max_attempts

    hdr(f"═══ WATCH: {svc} (every {interval}s) ═══")
    attempt = 0
    while True:
        active = service_is_active(systemd_name)
        ts = datetime.now().strftime("%H:%M:%S")
        if active:
            ok(f"[{ts}] {svc} is ACTIVE")
        else:
            fail(f"[{ts}] {svc} is DOWN — attempting restart ({attempt+1}/{max_attempts})")
            systemctl("restart", systemd_name)
            attempt += 1
            if max_attempts > 0 and attempt >= max_attempts:
                fail("Max restart attempts reached. Giving up.")
                break
        time.sleep(interval)


def cmd_checklist(_args):
    checklist = """
╔══════════════════════════════════════════════════════════════╗
║      BLUE TEAM CTF — SERVICE RESTORATION CHECKLIST           ║
╚══════════════════════════════════════════════════════════════╝

[ ] 1. SITUATIONAL AWARENESS
      python3 service_doctor.py check          # What's down?
      python3 service_doctor.py scan           # What's listening?
      systemctl --failed                        # Any crashed units?
      journalctl -xe                            # System-wide errors

[ ] 2. CHECK DISK SPACE (common cause of service failures)
      df -h
      du -sh /var/log/* | sort -rh | head -10  # Log bloat?

[ ] 3. CHECK MEMORY
      free -h
      top / htop

[ ] 4. CHECK PERMISSIONS
      ls -la /var/log/
      ls -la /etc/nginx/  # or relevant service dir

[ ] 5. ELASTICSEARCH
      python3 service_doctor.py fix elasticsearch
      curl -s http://localhost:9200/_cluster/health?pretty
      # Single-node discovery issue?
      echo 'discovery.type: single-node' >> /etc/elasticsearch/elasticsearch.yml
      # Heap?
      grep -r Xms /etc/elasticsearch/jvm.options

[ ] 6. KIBANA
      python3 service_doctor.py fix kibana
      # Check it can reach ES:
      curl -s http://localhost:9200  # Must work first
      grep elasticsearch.hosts /etc/kibana/kibana.yml

[ ] 7. SPLUNK
      /opt/splunk/bin/splunk status
      /opt/splunk/bin/splunk start --accept-license
      /opt/splunk/bin/splunk restart

[ ] 8. WEB SERVERS (nginx/apache)
      nginx -t && systemctl restart nginx
      apache2ctl configtest && systemctl restart apache2

[ ] 9. DATABASE (MySQL/MariaDB/PostgreSQL)
      python3 service_doctor.py fix mysql
      mysql -u root -e "SHOW DATABASES;"
      # PostgreSQL:
      sudo -u postgres psql -c "\\l"

[ ] 10. LOG SHIPPERS (Filebeat/Winlogbeat/Logstash)
       filebeat test config -c /etc/filebeat/filebeat.yml
       filebeat test output
       systemctl restart filebeat

[ ] 11. FIREWALL — ensure services are reachable
       ufw status
       iptables -L -n | grep -E "DROP|REJECT"
       # Temporarily allow everything for CTF:
       ufw disable  # (careful in real environments!)

[ ] 12. VERIFY SIEM DATA INGESTION
       # Elastic:
       curl -s "http://localhost:9200/_cat/indices?v" | grep -v ".kibana"
       curl -s "http://localhost:9200/_cat/count/*?v"
       # Splunk:
       /opt/splunk/bin/splunk search "index=* | stats count by index" -auth admin:password

[ ] 13. QUICK WIN — flag hunt immediately after services are up
       python3 /path/to/flag_hunter.py . --pattern 'ctf\\{[^}]+\\}'
       # In Splunk: index=* "ctf{" | table _time, _raw
       # In Kibana: message: "ctf{"
"""
    print(checklist)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Blue Team CTF service restoration & triage tool"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Quick health check of common services")
    p_check.add_argument("--services", help="Comma-separated list (default: common CTF set)")

    sub.add_parser("scan", help="Scan open ports + list failed systemd units")

    p_fix = sub.add_parser("fix", help="Attempt to restart/repair a service")
    p_fix.add_argument("service", help="Service name (e.g. nginx, elasticsearch)")
    p_fix.add_argument("--config", help="Override config path")

    p_watch = sub.add_parser("watch", help="Monitor & auto-restart a service")
    p_watch.add_argument("service")
    p_watch.add_argument("--interval", type=int, default=30,
                          help="Check interval in seconds (default 30)")
    p_watch.add_argument("--max-attempts", type=int, default=5,
                          help="Max restart attempts (0 = infinite)")

    sub.add_parser("checklist", help="Print Blue Team CTF service restoration checklist")

    args = parser.parse_args()
    dispatch = {
        "check": cmd_check,
        "scan": cmd_scan,
        "fix": cmd_fix,
        "watch": cmd_watch,
        "checklist": cmd_checklist,
    }
    dispatch[args.cmd](args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(0)
