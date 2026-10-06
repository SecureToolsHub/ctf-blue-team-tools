# elastic_siem

SIEM query construction tools and reference guides for Elastic Security and Kibana, tailored for threat detection, incident response, and forensic log correlation.

## Components

- **`elastic_query_builder.py`**: Parameterized CLI query generator producing KQL (Kibana Query Language), EQL (Event Query Language), Lucene, and Elasticsearch JSON DSL queries mapped to MITRE ATT&CK techniques.
- **`elastic_queries.md`**: Master reference cheat sheet with copy-paste detection queries for common attack vectors (brute-force, webshells, privilege escalation, lateral movement).

## Usage

```bash
# List all available query templates
python3 elastic_query_builder.py list

# Generate KQL query for brute force authentication
python3 elastic_query_builder.py brute_force --user "root"

# Generate EQL sequence query for process-network correlation
python3 elastic_query_builder.py webshell --format eql

# Export query to Elasticsearch JSON DSL
python3 elastic_query_builder.py lateral_movement --format es
```
