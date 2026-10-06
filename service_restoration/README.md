# service_restoration

A filesystem integrity baselining and differential analysis tool built to detect tampering, backdoor injection, and unintended modifications across critical service directories.

## Features

- **Baseline Snapshotting (`snapshot`)**: Traverses designated configuration and application directories (`/etc`, `/var/www`, `/opt`), computing recursive SHA-256 hashes and permission metadata.
- **Differential Detection (`diff`)**: Compares active filesystem state against a baseline snapshot, highlighting added, deleted, or altered files.
- **Triage Speed**: Enables defenders to immediately spot malicious payloads or configuration tampering introduced during an incident.

## Usage

```bash
# Generate baseline snapshot of critical service directories
python3 baseline_diff.py snapshot -o baseline.json --hash-dirs /etc,/var/www

# Diff live filesystem against saved baseline snapshot
python3 baseline_diff.py diff baseline.json --hash-dirs /etc,/var/www

# Export differences to JSON for automated alerting
python3 baseline_diff.py diff baseline.json --hash-dirs /etc,/var/www --json -o diff_report.json
```
