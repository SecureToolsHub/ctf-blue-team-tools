# dfir_triage

A live-response forensics acquisition script designed for rapid incident response on Linux hosts. It gathers critical volatile and non-volatile state data with zero third-party dependencies.

## Features

- **Volatile Execution State**: Running processes, deleted binaries executing from memory (`/proc/<pid>/exe`), and suspicious command-line parameters.
- **Network Sockets**: Established connections, listening sockets, and associated process IDs.
- **Persistence & User Accounts**: User logins, active sessions, sudoers rules, and crontabs across users.
- **Structured Export**: Outputs findings to clean terminal summaries, JSON data dumps, or archived `.tar.gz` preservation bundles.

## Usage

```bash
# Rapid terminal triage (3-second vital signs check)
python3 dfir_triage.py quick

# Comprehensive triage exported to structured JSON
python3 dfir_triage.py full -o /tmp/incident_triage.json

# Complete forensic preservation bundle archived as tarball
python3 dfir_triage.py tar -o /tmp/incident_evidence.tar.gz
```
