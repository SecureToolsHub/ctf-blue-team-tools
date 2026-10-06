import json
import argparse
import sys
import os
from dataclasses import dataclass, asdict, field
from typing import List, Optional, Dict, Any
from datetime import datetime

MITRE_TECHNIQUES: Dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1053": "Scheduled Task/Job",
    "T1534": "Internal Spearphishing",
    "T1572": "Protocol Tunneling",
    "T1003": "OS Credential Dumping",
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1082": "System Information Discovery",
    "T1552": "Unsecured Credentials",
    "T1136": "Create Account"
}

@dataclass
class IoC:
    """Represents an Indicator of Compromise."""
    type: str
    value: str
    technique_id: str
    tactic: str
    timestamp: str
    source: str
    confidence: str
    notes: Optional[str] = None

@dataclass
class Event:
    """Represents a discrete event in the attack timeline."""
    timestamp: str
    technique_id: str
    tactic: str
    description: str
    evidence: str
    host: str
    user: str

@dataclass
class Finding:
    """Represents a discovered vulnerability or security issue."""
    id: str
    severity: str
    title: str
    description: str
    affected_component: str
    remediation_steps: str

@dataclass
class ReportState:
    """Represents the complete incident report data structure."""
    incident_id: str
    date: str
    analyst: str
    team: str
    iocs: List[IoC] = field(default_factory=list)
    events: List[Event] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReportState':
        """Instantiate a ReportState from a dictionary."""
        return cls(
            incident_id=data.get('incident_id', 'UNKNOWN'),
            date=data.get('date', datetime.utcnow().isoformat()),
            analyst=data.get('analyst', 'Unknown Analyst'),
            team=data.get('team', 'Unknown Team'),
            iocs=[IoC(**ioc) for ioc in data.get('iocs', [])],
            events=[Event(**evt) for evt in data.get('events', [])],
            findings=[Finding(**fnd) for fnd in data.get('findings', [])]
        )

def load_report(filepath: str) -> ReportState:
    """Loads a report state from a JSON file."""
    if not os.path.exists(filepath):
        print(f"Error: File {filepath} does not exist.", file=sys.stderr)
        sys.exit(1)
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
        return ReportState.from_dict(data)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {filepath}: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error loading report: {e}", file=sys.stderr)
        sys.exit(1)

def save_report(report: ReportState, filepath: str) -> None:
    """Saves a report state to a JSON file."""
    try:
        with open(filepath, 'w') as f:
            json.dump(asdict(report), f, indent=4)
        print(f"Report state successfully saved to {filepath}")
    except Exception as e:
        print(f"Error saving report to {filepath}: {e}", file=sys.stderr)
        sys.exit(1)

def handle_new(args: argparse.Namespace) -> None:
    """Handles the 'new' subcommand."""
    report = ReportState(
        incident_id=args.id,
        date=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        analyst=args.analyst,
        team=args.team
    )
    save_report(report, args.out)

def handle_add_ioc(args: argparse.Namespace) -> None:
    """Handles the 'add-ioc' subcommand."""
    report = load_report(args.file)
    ioc = IoC(
        type=args.type,
        value=args.value,
        technique_id=args.technique,
        tactic=args.tactic,
        timestamp=args.timestamp,
        source=args.source,
        confidence=args.confidence,
        notes=args.notes
    )
    report.iocs.append(ioc)
    save_report(report, args.file)

def handle_add_event(args: argparse.Namespace) -> None:
    """Handles the 'add-event' subcommand."""
    report = load_report(args.file)
    event = Event(
        timestamp=args.timestamp,
        technique_id=args.technique,
        tactic=args.tactic,
        description=args.description,
        evidence=args.evidence,
        host=args.host,
        user=args.user
    )
    report.events.append(event)
    save_report(report, args.file)

def handle_add_finding(args: argparse.Namespace) -> None:
    """Handles the 'add-finding' subcommand."""
    report = load_report(args.file)
    finding = Finding(
        id=args.id,
        severity=args.severity,
        title=args.title,
        description=args.description,
        affected_component=args.component,
        remediation_steps=args.remediation
    )
    report.findings.append(finding)
    save_report(report, args.file)

def handle_generate(args: argparse.Namespace) -> None:
    """Handles the 'generate' subcommand, exporting the state to Markdown."""
    report = load_report(args.file)
    out_file = args.out

    lines = []
    lines.append(f"# Incident Report: {report.incident_id}")
    lines.append(f"**Date:** {report.date}  ")
    lines.append(f"**Analyst:** {report.analyst}  ")
    lines.append(f"**Team:** {report.team}  \n")

    lines.append("## Executive Summary")
    lines.append("This report details the findings, timeline, and indicators of compromise (IoCs) associated with the investigation. The narrative encompasses initial access, privilege escalation, persistence, and lateral movement.\n")

    lines.append("## Attack Timeline")
    if not report.events:
        lines.append("*No events recorded.*\n")
    else:
        # Sort events chronologically
        sorted_events = sorted(report.events, key=lambda e: e.timestamp)
        for event in sorted_events:
            mitre_name = MITRE_TECHNIQUES.get(event.technique_id, "Unknown Technique")
            lines.append(f"### {event.timestamp} - {event.tactic} ({event.technique_id}: {mitre_name})")
            lines.append(f"**Host:** {event.host} | **User:** {event.user}")
            lines.append(f"\n{event.description}\n")
            lines.append("**Evidence:**")
            lines.append("```")
            lines.append(event.evidence)
            lines.append("```\n")

    lines.append("## Findings & Remediation")
    if not report.findings:
        lines.append("*No findings recorded.*\n")
    else:
        for finding in report.findings:
            lines.append(f"### [{finding.id}] {finding.title} ({finding.severity.upper()})")
            lines.append(f"**Affected Component:** {finding.affected_component}\n")
            lines.append(f"**Description:**\n{finding.description}\n")
            lines.append(f"**Remediation Steps:**\n{finding.remediation_steps}\n")

    lines.append("## Indicators of Compromise (IoC)")
    if not report.iocs:
        lines.append("*No IoCs recorded.*\n")
    else:
        lines.append("| Type | Value | Technique | Confidence | Source | Notes |")
        lines.append("|------|-------|-----------|------------|--------|-------|")
        for ioc in report.iocs:
            notes = ioc.notes if ioc.notes else ""
            lines.append(f"| {ioc.type} | `{ioc.value}` | {ioc.technique_id} | {ioc.confidence} | {ioc.source} | {notes} |")
        lines.append("\n")

    lines.append("## Conclusions & Recommendations")
    lines.append("Implement the remediation steps identified above to close existing security gaps. Continuously monitor for the identified IoCs and consider hardening systemic infrastructure based on the attack timeline patterns.\n")

    # Score helper block (invisible in rendered if we wanted, but good for local review)
    lines.append("---")
    lines.append("### Assessed Score completeness")
    score_text = calculate_score(report)
    lines.append(f"```\n{score_text}\n```\n")

    try:
        with open(out_file, 'w') as f:
            f.write('\n'.join(lines))
        print(f"Markdown report generated at {out_file}")
    except Exception as e:
        print(f"Error generating markdown report: {e}", file=sys.stderr)
        sys.exit(1)

def calculate_score(report: ReportState) -> str:
    """Calculates and formats the estimated report score."""
    score_lines = []
    
    # 60% Timeline / Logs
    timeline_score = 0
    if len(report.events) >= 5:
        timeline_score = 60
    elif len(report.events) > 0:
        timeline_score = int(60 * (len(report.events) / 5))
    score_lines.append(f"Timeline/Log Evidence (60% weight): ~{timeline_score}/60")

    # 30% Remediation
    remed_score = 0
    if len(report.findings) >= 3:
        remed_score = 30
    elif len(report.findings) > 0:
        remed_score = int(30 * (len(report.findings) / 3))
    score_lines.append(f"Remediation Recommendations (30% weight): ~{remed_score}/30")

    # 10% Narrative
    narrative_score = 10 if timeline_score > 30 and remed_score > 15 else 5
    score_lines.append(f"Narrative/Conclusions (10% weight): ~{narrative_score}/10")

    total_base = timeline_score + remed_score + narrative_score
    score_lines.append(f"Estimated Narrative Score: {total_base}/100")

    # IoC Score
    ioc_count = min(len(report.iocs), 20)
    ioc_score = ioc_count * 100
    score_lines.append(f"IoC Submissions Score: {ioc_score} ({ioc_count}/20 max paid IoCs)")

    return "\n".join(score_lines)

def handle_score_check(args: argparse.Namespace) -> None:
    """Handles the 'score-check' subcommand."""
    report = load_report(args.file)
    print(f"--- Score Check for {report.incident_id} ---")
    print(calculate_score(report))

def handle_ioc_list(args: argparse.Namespace) -> None:
    """Handles the 'ioc-list' subcommand."""
    report = load_report(args.file)
    for i, ioc in enumerate(report.iocs, start=1):
        print(f"[{i:02d}] {ioc.type.upper()}: {ioc.value}")
        print(f"     Technique: {ioc.technique_id} ({MITRE_TECHNIQUES.get(ioc.technique_id, 'Unknown')})")
        print(f"     Source: {ioc.source} | Confidence: {ioc.confidence}")
        print(f"     Tactic: {ioc.tactic}")
        if ioc.notes:
            print(f"     Notes: {ioc.notes}")
        print("-" * 40)
    print(f"Total IoCs: {len(report.iocs)}")

def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(description="CTF Incident Report Builder")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser: new
    parser_new = subparsers.add_parser("new", help="Initialize a new incident report")
    parser_new.add_argument("-o", "--out", required=True, help="Output JSON file path")
    parser_new.add_argument("--id", required=True, help="Incident ID")
    parser_new.add_argument("--analyst", required=True, help="Analyst Name")
    parser_new.add_argument("--team", required=True, help="Team Name")

    # Subparser: add-ioc
    parser_ioc = subparsers.add_parser("add-ioc", help="Add an Indicator of Compromise")
    parser_ioc.add_argument("--file", required=True, help="Target JSON report file")
    parser_ioc.add_argument("--type", required=True, choices=["ip", "hash", "domain", "file", "url", "email", "tool", "username", "service"], help="IoC Type")
    parser_ioc.add_argument("--value", required=True, help="IoC Value")
    parser_ioc.add_argument("--technique", required=True, help="MITRE Technique ID (e.g., T1190)")
    parser_ioc.add_argument("--tactic", required=True, help="MITRE Tactic")
    parser_ioc.add_argument("--timestamp", required=True, help="Detection Timestamp")
    parser_ioc.add_argument("--source", required=True, help="Source of detection (e.g., log file line)")
    parser_ioc.add_argument("--confidence", required=True, choices=["high", "medium", "low"], help="Confidence level")
    parser_ioc.add_argument("--notes", help="Optional context or notes")

    # Subparser: add-event
    parser_event = subparsers.add_parser("add-event", help="Add a timeline event")
    parser_event.add_argument("--file", required=True, help="Target JSON report file")
    parser_event.add_argument("--timestamp", required=True, help="Event Timestamp")
    parser_event.add_argument("--technique", required=True, help="MITRE Technique ID")
    parser_event.add_argument("--tactic", required=True, help="MITRE Tactic")
    parser_event.add_argument("--description", required=True, help="Description of the event")
    parser_event.add_argument("--evidence", required=True, help="Log snippets or raw evidence")
    parser_event.add_argument("--host", required=True, help="Target host")
    parser_event.add_argument("--user", required=True, help="Target user")

    # Subparser: add-finding
    parser_finding = subparsers.add_parser("add-finding", help="Add a vulnerability finding")
    parser_finding.add_argument("--file", required=True, help="Target JSON report file")
    parser_finding.add_argument("--id", required=True, help="Finding ID (e.g., VULN-01)")
    parser_finding.add_argument("--severity", required=True, choices=["critical", "high", "medium", "low"], help="Severity")
    parser_finding.add_argument("--title", required=True, help="Finding title")
    parser_finding.add_argument("--description", required=True, help="Detailed description")
    parser_finding.add_argument("--component", required=True, help="Affected component or service")
    parser_finding.add_argument("--remediation", required=True, help="Remediation steps")

    # Subparser: generate
    parser_generate = subparsers.add_parser("generate", help="Generate the Markdown report")
    parser_generate.add_argument("--file", required=True, help="Target JSON report file")
    parser_generate.add_argument("-o", "--out", required=True, help="Output Markdown file path")

    # Subparser: ioc-list
    parser_ioc_list = subparsers.add_parser("ioc-list", help="List all IoCs formatted for submission")
    parser_ioc_list.add_argument("--file", required=True, help="Target JSON report file")

    # Subparser: score-check
    parser_score = subparsers.add_parser("score-check", help="Check estimated completion score")
    parser_score.add_argument("--file", required=True, help="Target JSON report file")

    args = parser.parse_args()

    # Route to handlers
    if args.command == "new":
        handle_new(args)
    elif args.command == "add-ioc":
        handle_add_ioc(args)
    elif args.command == "add-event":
        handle_add_event(args)
    elif args.command == "add-finding":
        handle_add_finding(args)
    elif args.command == "generate":
        handle_generate(args)
    elif args.command == "ioc-list":
        handle_ioc_list(args)
    elif args.command == "score-check":
        handle_score_check(args)

if __name__ == "__main__":
    main()
