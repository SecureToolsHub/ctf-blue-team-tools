# web_config_auditor

An offline security configuration auditor and webshell scanner for web servers, application runtimes, and databases.

## Features

- **Offline Configuration Parsing**: Inspects configuration files without requiring live network requests or service restarts. Supports:
  - **Web & Proxy**: Nginx, PHP (`php.ini`, PHP-FPM).
  - **Databases**: MySQL/MariaDB (`my.cnf`), PostgreSQL (`pg_hba.conf`, `postgresql.conf`).
  - **Applications**: GitLab, Roundcube Webmail.
- **Webshell Scanner (`webshell`)**: Signature and regex-based scanning of webroots for PHP/JSP webshells, obfuscated payloads, and evaluation wrappers.
- **Safe Auto-Fix**: Automatically generates `.bak` backups before modifying configurations.

## Usage

```bash
# Run full offline audit across all supported services
python3 web_config_auditor.py audit

# Scan web directory for webshells
python3 web_config_auditor.py webshell /var/www/html

# Audit specific service configuration
python3 web_config_auditor.py audit --service nginx
```
