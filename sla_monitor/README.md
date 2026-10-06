# sla_monitor

A real-time service availability monitor and watchdog daemon engineered to protect SLA uptime scores during CTF defense operations.

## Features

- **Service Status Polling (`check`)**: Verifies process states, open socket listeners, and HTTP 200 health check endpoints. Categorizes status into Active, Degraded, Vulnerable, or Down.
- **Continuous Watchdog (`watch`)**: Daemon mode running periodic polls; automatically restarts failing services via systemd and logs downtime events.
- **Service Hardening Advice (`harden`)**: Generates actionable, service-specific hardening checklists (permissions, config flags).
- **Incident SLA Reporting (`report`)**: Aggregates outage logs into an uptime report showing downtime seconds and SLA percentages.

## Usage

```bash
# Check status across all configured services
python3 sla_monitor.py check

# Run continuous monitoring watchdog with auto-recovery
python3 sla_monitor.py watch --interval 30

# Generate service hardening checklist
python3 sla_monitor.py harden nginx

# Generate SLA compliance report from watchdog logs
python3 sla_monitor.py report -o sla_report.md
```
