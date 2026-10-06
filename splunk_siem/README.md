# splunk_siem

Splunk Search Processing Language (SPL) query tools and cheat sheets for Blue Team investigations and threat hunting.

## Components

- **`splunk_query_builder.py`**: Parameterized CLI query generator producing optimized SPL searches from built-in templates (brute-force, webshell activity, privilege escalation, lateral movement).
- **`splunk_queries.md`**: Master reference cheat sheet containing ready-to-run SPL searches organized by scenario and attack vector.

## Usage

```bash
# List available SPL query templates
python3 splunk_query_builder.py list

# Generate SPL query for brute force authentication
python3 splunk_query_builder.py brute_force --index "wineventlog"

# Generate SPL query for web application attack hunting
python3 splunk_query_builder.py webshell --index "web_logs"

# Generate query with custom time window
python3 splunk_query_builder.py failed_logins --earliest "-4h" --latest "now"
```
