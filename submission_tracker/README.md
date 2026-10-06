# submission_tracker

A state-machine submission manager for CTF operations ensuring strict rule adherence and tracking submitted Indicators of Compromise (IoCs) and incident reports.

## Features

- **Rule Enforcement**: Prevents invalid submissions, deduplicates submitted IoCs, and enforces strict operational limits (e.g. max submissions, sequence locking).
- **Audit Ledger**: Maintains a local JSON state ledger recording every submission with timestamps, MITRE ATT&CK techniques, and validation results.
- **Progress Tracking**: Provides immediate visual summaries of submitted indicators, acceptance status, and remaining quota.

## Usage

```bash
# Initialize competition tracking session
python3 submission_tracker.py init --team "BlueOps" --incident-id "INC-01"

# Record submitted IoC
python3 submission_tracker.py add-ioc --type ip --value "198.51.100.12" --technique "T1190"

# Check submission progress and quota
python3 submission_tracker.py status

# Export verified submissions to report format
python3 submission_tracker.py export -o submitted_iocs.json
```
