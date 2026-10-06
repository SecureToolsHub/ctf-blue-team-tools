# persistence_hunter

A comprehensive Linux persistence mechanism auditor built to hunt down attacker backdoors, autostart entries, and privilege escalation traps.

## Features

- **Scheduled Tasks**: Inspects user and system crontabs (`/etc/cron*`, `/var/spool/cron/crontabs`), systemd timers, and `at` jobs.
- **Service Hooks**: Scans systemd service unit definitions, overrides, and legacy `init.d` / `rc.local` scripts.
- **Shell & User Startup**: Audits global and user-specific shell initialization files (`.bashrc`, `.profile`, `/etc/profile.d/`, `/etc/environment`).
- **Authentication & Binaries**: Checks SSH `authorized_keys`, PAM modules, SUID/SGID binaries, and recently modified system binaries.

## Usage

```bash
# Run full automated persistence audit
python3 persistence_hunter.py audit

# Audit only systemd services and timers
python3 persistence_hunter.py systemd

# Audit cron schedules across all users
python3 persistence_hunter.py cron

# Export full audit results to JSON
python3 persistence_hunter.py audit --json -o persistence_findings.json
```
