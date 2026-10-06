# vuln_patcher

An automated vulnerability audit and remediation engine for Linux hosts, focusing on privilege escalation and persistence avenues.

## Features

- **Automated Audit (`audit`)**: Identifies insecure permissions, risky SUID/SGID binaries, world-writable critical files, dangerous sudoers NOPASSWD directives, insecure SSH configurations, and unauthorized listening services.
- **Idempotent Patching (`patch`, `patch-all`)**: Applies hardened configurations and permissions without breaking active processes or services.
- **Verification (`verify`)**: Confirms patches have been successfully applied and verified.

## Vulnerabilities Covered
- `suid_sgid`
- `cron_persistence`
- `systemd_backdoor`
- `weak_ssh_config`
- `world_writable`
- `sudoers_nopasswd`
- `listening_backdoor`

## Usage

```bash
# Run vulnerability audit across host
python3 vuln_patcher.py audit

# Apply all automatic security patches
sudo python3 vuln_patcher.py patch-all

# Apply a specific targeted patch
sudo python3 vuln_patcher.py patch weak_ssh_config

# Verify patch effectiveness
python3 vuln_patcher.py verify weak_ssh_config
```
