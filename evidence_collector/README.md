# evidence_collector

A structured digital evidence collection tool ensuring strict forensic integrity, cryptographic verification, and chain of custody documentation.

## Features

- **Cryptographic Hashing**: Automatically calculates MD5 and SHA-256 hashes for every acquired evidence item upon ingestion.
- **Chain of Custody Tracking**: Generates machine-readable provenance logs recording collector identity, timestamps, source paths, and file attributes.
- **Directory Ingestion**: Safely copies and indexes target evidence directories without mutating file metadata.

## Usage

```bash
# Ingest single file or directory into evidence repository
python3 evidence_collector.py collect /var/log/nginx -o ./case_evidence --case "INC-2026-001"

# Verify integrity of previously collected evidence against saved hashes
python3 evidence_collector.py verify ./case_evidence

# Generate evidence index and chain-of-custody report
python3 evidence_collector.py manifest ./case_evidence -o manifest.json
```
