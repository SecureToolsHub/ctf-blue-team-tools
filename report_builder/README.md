# report_builder

An automated reporting tool for DFIR investigations and Blue Team CTF competitions. Generates structured, professional Incident Response reports with executive summaries, attack chronologies, and remediation guidance.

## Features

- **Standardized Incident Template**: Assembles executive summary, attack vector analysis, technical impact, chronological event timeline, verified IoC catalog, and remediation recommendations.
- **Dynamic Artifact Ingestion**: Ingests JSON IoC catalogs (from `ioc_hunter`) and CSV timelines (from `log_timeline`).
- **Scoring & Compliance Verification**: Validates report contents against standard competition scoring weightings (Timeline accuracy, Remediation quality, Narrative completeness).

## Usage

```bash
# Generate complete Incident Response report
python3 report_builder.py generate \
  --incident "INC-2026-001" \
  --team "BlueOps" \
  --iocs /path/to/iocs.json \
  --timeline /path/to/timeline.csv \
  --output incident_report.md

# Verify report structure and score criteria
python3 report_builder.py score-check incident_report.md
```
