# cod_fixer

A code and service configuration repair utility designed to recover downed services by diagnosing and resolving formatting, encoding, and syntax errors.

## Components

- **`code_doctor.py`**: Safe offline auto-repair engine for scripts and service configurations.
  - Detects and removes UTF-8 BOM headers.
  - Normalizes line endings (CRLF -> LF).
  - Harmonizes mixed tab and space indentation.
  - Strips trailing whitespace and verifies syntax.
  - Performs network port and systemd service verification.
- **`code_fixer_v2`**: AI-assisted logic repair client interface.

## Usage

```bash
# Dry-run inspection of configuration or source file
python3 code_doctor.py /etc/nginx/nginx.conf

# Apply safe formatting repairs in-place
python3 code_doctor.py /etc/nginx/nginx.conf --apply

# Verify service status and listening ports after repair
python3 code_doctor.py --check-service nginx --check-port 80
```
