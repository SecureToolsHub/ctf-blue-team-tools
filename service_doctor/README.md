# service_doctor

A rapid service triage and diagnostic recovery tool for critical Linux server daemons during compromise or outage events.

## Features

- **Automated Health Checks (`check`)**: Verifies status of common CTF services (Nginx, Apache, MySQL, PostgreSQL, Redis, SSH, GitLab, Roundcube) across process state and port availability.
- **Port & Unit Scan (`scan`)**: Scans for failed systemd units and unexpected listening ports.
- **Guided Recovery (`fix`)**: Diagnoses failure causes (broken permissions, missing directories, port collisions) and attempts automated remediation.

## Usage

```bash
# Run health check across all registered critical services
python3 service_doctor.py check

# Scan system for failed systemd units and listening sockets
python3 service_doctor.py scan

# Diagnose and attempt automated recovery on a specific service
sudo python3 service_doctor.py fix nginx
sudo python3 service_doctor.py fix mysql
```
