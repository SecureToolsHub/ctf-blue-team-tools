# artifact_hunter

A multi-mode digital forensics and incident response (DFIR) artifact discovery tool. It sweeps target directories, forensic mounts, or live root filesystems to locate critical OS artifacts, credential stores, and recently altered files.

## Features

- **Path Sweeper (`paths`)**: Identifies high-value security files (SSH private/public keys, AWS credentials, browser SQLite profiles, shell histories, `.env` files, and database configs).
- **Credential Hunter (`creds`)**: Scans file contents for regex patterns matching API tokens, JWTs, private keys, database connection strings, and generic secrets.
- **Recent Modification Filter (`recent`)**: Surfaces files created or modified within a specified time window.

## Usage

```bash
# Locate high-value files across evidence or live filesystem
python3 artifact_hunter.py paths /mnt/evidence -o artifacts.txt

# Scan files for exposed credentials and secrets
python3 artifact_hunter.py creds /mnt/evidence -o creds_found.txt

# Detect files modified within the last N hours
python3 artifact_hunter.py recent /mnt/evidence --hours 24
```
