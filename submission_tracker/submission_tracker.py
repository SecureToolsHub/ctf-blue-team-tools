#!/usr/bin/env python3
"""
Cyberkent 4.0 Competition Submission Tracker
Single source of truth for competition state machine and submissions.
Enforces strict competition rules for IoCs and Reports.
"""

import argparse
import dataclasses
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional

# ==========================================
# CONSTANTS & ANSI COLORS
# ==========================================

MAX_IOC_SUBMISSIONS = 100
MAX_REPORT_SUBMISSIONS = 3
TOTAL_IOCS_TO_FIND = 20
POINTS_PER_IOC = 100
COMPETITION_DURATION_HOURS = 48  # Assumed for time warnings

class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"


# ==========================================
# DATAMODELS
# ==========================================

@dataclasses.dataclass
class IoCSubmission:
    """Represents a single IoC submission."""
    id: str
    ioc_type: str
    value: str
    technique: str
    tactic: str
    confidence: str
    notes: str
    status: str
    timestamp: str

@dataclasses.dataclass
class ReportSubmission:
    """Represents a single report submission."""
    id: str
    version: int
    notes: str
    status: str
    timestamp: str

@dataclasses.dataclass
class AuditEntry:
    """Represents an action taken within the tracker."""
    timestamp: str
    action: str
    details: str

@dataclasses.dataclass
class CompetitionState:
    """The root state machine model for the competition."""
    team: str
    incident_id: str
    start_time: str
    iocs: List[IoCSubmission]
    reports: List[ReportSubmission]
    ioc_submission_locked: bool
    audit_log: List[AuditEntry]


# ==========================================
# CORE ENGINE
# ==========================================

def get_now() -> str:
    """Returns current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def load_state(filepath: str) -> CompetitionState:
    """Loads the competition state from a JSON file."""
    if not os.path.exists(filepath):
        print(f"{Colors.RED}{Colors.BOLD}[!] State file not found: {filepath}{Colors.RESET}")
        print(f"Run 'init' to create a new session.")
        sys.exit(1)
        
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
            
        iocs = [IoCSubmission(**ioc) for ioc in data.get("iocs", [])]
        reports = [ReportSubmission(**rep) for rep in data.get("reports", [])]
        audits = [AuditEntry(**aud) for aud in data.get("audit_log", [])]
        
        return CompetitionState(
            team=data["team"],
            incident_id=data["incident_id"],
            start_time=data["start_time"],
            iocs=iocs,
            reports=reports,
            ioc_submission_locked=data.get("ioc_submission_locked", False),
            audit_log=audits
        )
    except Exception as e:
        print(f"{Colors.RED}{Colors.BOLD}[!] Failed to parse state file: {e}{Colors.RESET}")
        sys.exit(1)

def save_state(state: CompetitionState, filepath: str) -> None:
    """
    Saves the state atomically to avoid corruption.
    Uses tempfile and os.replace.
    """
    dir_name = os.path.dirname(os.path.abspath(filepath))
    os.makedirs(dir_name, exist_ok=True)
    
    # Dump to dict
    data = dataclasses.asdict(state)
    
    try:
        fd, temp_path = tempfile.mkstemp(dir=dir_name, prefix=".ctf_state_")
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            
        # Atomic replace
        os.replace(temp_path, filepath)
    except Exception as e:
        print(f"{Colors.RED}{Colors.BOLD}[!] Failed to write state file atomically: {e}{Colors.RESET}")
        sys.exit(1)

def log_audit(state: CompetitionState, action: str, details: str) -> None:
    """Appends an audit event to the state machine."""
    state.audit_log.append(AuditEntry(
        timestamp=get_now(),
        action=action,
        details=details
    ))


# ==========================================
# COMMAND HANDLERS
# ==========================================

def handle_init(args: argparse.Namespace) -> None:
    if os.path.exists(args.state) and not getattr(args, 'force', False):
        print(f"{Colors.RED}[!] State file {args.state} already exists.{Colors.RESET}")
        print("Use a different file or manually remove it.")
        sys.exit(1)
        
    state = CompetitionState(
        team=args.team,
        incident_id=args.incident_id,
        start_time=get_now(),
        iocs=[],
        reports=[],
        ioc_submission_locked=False,
        audit_log=[]
    )
    
    log_audit(state, "INIT", f"Initialized session for team {args.team}, incident {args.incident_id}")
    save_state(state, args.state)
    print(f"{Colors.GREEN}[+] Competition session initialized at {args.state}{Colors.RESET}")


def handle_add_ioc(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    # HARD BLOCK: Is locked?
    if state.ioc_submission_locked:
        print(f"{Colors.RED}{Colors.BOLD}[!] RULE VIOLATION (Code 2): IoC submissions are locked. A report has already been ACCEPTED.{Colors.RESET}")
        sys.exit(2)
        
    # HARD BLOCK: Max submissions reached?
    if len(state.iocs) >= MAX_IOC_SUBMISSIONS:
        print(f"{Colors.RED}{Colors.BOLD}[!] RULE VIOLATION (Code 2): Maximum IoC submissions ({MAX_IOC_SUBMISSIONS}) reached.{Colors.RESET}")
        sys.exit(2)
        
    # WARNINGS
    if len(state.iocs) >= 95:
        print(f"{Colors.RED}{Colors.BOLD}[!] WARNING: You are approaching the absolute limit. ({len(state.iocs)}/{MAX_IOC_SUBMISSIONS}){Colors.RESET}")
    elif len(state.iocs) >= 90:
        print(f"{Colors.YELLOW}[!] WARNING: Submissions high. ({len(state.iocs)}/{MAX_IOC_SUBMISSIONS}){Colors.RESET}")

    ioc = IoCSubmission(
        id=str(uuid.uuid4())[:8],
        ioc_type=args.type,
        value=args.value,
        technique=args.technique,
        tactic=args.tactic,
        confidence=args.confidence,
        notes=args.notes or "",
        status=args.status,
        timestamp=get_now()
    )
    
    state.iocs.append(ioc)
    log_audit(state, "ADD_IOC", f"Added IoC {ioc.id} ({ioc.value}) with status {ioc.status}")
    save_state(state, args.state)
    
    print(f"{Colors.GREEN}[+] Added IoC Submission ID: {ioc.id}{Colors.RESET}")
    print(f"    Current count: {len(state.iocs)}/{MAX_IOC_SUBMISSIONS} (Remaining: {MAX_IOC_SUBMISSIONS - len(state.iocs)})")


def handle_update_ioc(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    target = next((i for i in state.iocs if i.id == args.id), None)
    if not target:
        print(f"{Colors.RED}[!] IoC with ID {args.id} not found.{Colors.RESET}")
        sys.exit(1)
        
    old_status = target.status
    target.status = args.status
    
    log_audit(state, "UPDATE_IOC", f"IoC {target.id} status changed: {old_status} -> {args.status}")
    save_state(state, args.state)
    
    print(f"{Colors.GREEN}[+] IoC {target.id} updated to {args.status}{Colors.RESET}")


def handle_submit_report(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    # HARD BLOCK: Must have submitted IoCs first
    if len(state.iocs) == 0:
        print(f"{Colors.RED}{Colors.BOLD}[!] RULE VIOLATION (Code 2): §10.4 Enforces IoCs must be submitted BEFORE the report.{Colors.RESET}")
        sys.exit(2)
        
    # HARD BLOCK: Max reports reached?
    if len(state.reports) >= MAX_REPORT_SUBMISSIONS:
        print(f"{Colors.RED}{Colors.BOLD}[!] RULE VIOLATION (Code 2): Maximum report submissions ({MAX_REPORT_SUBMISSIONS}) reached.{Colors.RESET}")
        sys.exit(2)
        
    # Check if a report is already accepted
    if any(r.status == 'accepted' for r in state.reports):
        print(f"{Colors.RED}{Colors.BOLD}[!] RULE VIOLATION (Code 2): A report is already accepted. Cannot submit again.{Colors.RESET}")
        sys.exit(2)

    if len(state.reports) == 1:
        print(f"{Colors.YELLOW}[!] WARNING: This is report submission 2/{MAX_REPORT_SUBMISSIONS}.{Colors.RESET}")
    elif len(state.reports) == 2:
        print(f"{Colors.YELLOW}[!] WARNING: This is your LAST chance (submission 3/{MAX_REPORT_SUBMISSIONS}).{Colors.RESET}")

    rep = ReportSubmission(
        id=str(uuid.uuid4())[:8],
        version=args.version,
        notes=args.notes or "",
        status="review",
        timestamp=get_now()
    )
    
    state.reports.append(rep)
    log_audit(state, "SUBMIT_REPORT", f"Submitted report v{rep.version} (ID: {rep.id})")
    save_state(state, args.state)
    
    print(f"{Colors.GREEN}[+] Report v{rep.version} submitted (ID: {rep.id}){Colors.RESET}")
    print(f"    Submissions remaining: {MAX_REPORT_SUBMISSIONS - len(state.reports)}")


def handle_update_report(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    target = next((r for r in state.reports if r.version == args.version), None)
    if not target:
        print(f"{Colors.RED}[!] Report with version {args.version} not found.{Colors.RESET}")
        sys.exit(1)
        
    old_status = target.status
    target.status = args.status
    
    msg = f"Report v{target.version} status changed: {old_status} -> {args.status}"
    
    if args.status == "accepted":
        state.ioc_submission_locked = True
        msg += ". IoC submissions are now LOCKED."
        
    log_audit(state, "UPDATE_REPORT", msg)
    save_state(state, args.state)
    
    print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")


def handle_status(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    try:
        start_dt = datetime.fromisoformat(state.start_time.replace("Z", "+00:00"))
        now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
        start_dt_naive = start_dt.replace(tzinfo=None)
        elapsed = now_dt - start_dt_naive
        remaining = timedelta(hours=COMPETITION_DURATION_HOURS) - elapsed
    except Exception:
        elapsed = timedelta(0)
        remaining = timedelta(0)

    # IoC Stats
    ioc_count = len(state.iocs)
    confirmed_iocs = [i for i in state.iocs if i.status == "confirmed"]
    rejected_iocs = [i for i in state.iocs if i.status == "rejected"]
    pending_iocs = [i for i in state.iocs if i.status == "pending"]
    
    # Projected score
    current_score = len(confirmed_iocs) * POINTS_PER_IOC
    
    # Reports
    report_count = len(state.reports)

    print(f"\n{Colors.BOLD}{Colors.CYAN}=== CYBERKENT 4.0 COMPETITION DASHBOARD ==={Colors.RESET}\n")
    print(f" {Colors.BOLD}Team:{Colors.RESET} {state.team}  |  {Colors.BOLD}Incident ID:{Colors.RESET} {state.incident_id}")
    print(f" {Colors.BOLD}Started:{Colors.RESET} {state.start_time}")
    print(f" {Colors.BOLD}Elapsed Time:{Colors.RESET} {str(elapsed).split('.')[0]}")
    
    # Time warnings
    if remaining.total_seconds() < 30 * 60:
        print(f" {Colors.RED}{Colors.BOLD}[!] RED WARNING: Less than 30 minutes remaining!{Colors.RESET}")
    elif remaining.total_seconds() < 2 * 3600:
        print(f" {Colors.YELLOW}{Colors.BOLD}[!] YELLOW WARNING: Less than 2 hours remaining!{Colors.RESET}")

    print(f"\n{Colors.BOLD}--- IoC Submissions ---{Colors.RESET}")
    print(f" Count: {ioc_count}/{MAX_IOC_SUBMISSIONS}")
    print(f" Breakdown: {Colors.GREEN}{len(confirmed_iocs)} Confirmed{Colors.RESET} | "
          f"{Colors.YELLOW}{len(pending_iocs)} Pending{Colors.RESET} | "
          f"{Colors.RED}{len(rejected_iocs)} Rejected{Colors.RESET}")
          
    if state.ioc_submission_locked:
        print(f" {Colors.RED}{Colors.BOLD}[LOCKED]{Colors.RESET} No further IoCs can be submitted.")

    print(f"\n{Colors.BOLD}--- Report Submissions ---{Colors.RESET}")
    print(f" Count: {report_count}/{MAX_REPORT_SUBMISSIONS}")
    for r in state.reports:
        color = Colors.GREEN if r.status == 'accepted' else (Colors.RED if r.status == 'rejected' else Colors.YELLOW)
        print(f"  - v{r.version}: {color}{r.status.upper()}{Colors.RESET} (ID: {r.id})")

    print(f"\n{Colors.BOLD}--- Rule Status ---{Colors.RESET}")
    ioc_before_report = "PASS" if len(state.iocs) > 0 or len(state.reports) == 0 else "FAIL"
    print(f" IoCs before Report rule: {Colors.GREEN if ioc_before_report=='PASS' else Colors.RED}{ioc_before_report}{Colors.RESET}")
    print(f" Submissions limit: {Colors.GREEN if ioc_count <= MAX_IOC_SUBMISSIONS else Colors.RED}{'PASS' if ioc_count <= MAX_IOC_SUBMISSIONS else 'FAIL'}{Colors.RESET}")
    print(f" Report limit: {Colors.GREEN if report_count <= MAX_REPORT_SUBMISSIONS else Colors.RED}{'PASS' if report_count <= MAX_REPORT_SUBMISSIONS else 'FAIL'}{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}--- Projection ---{Colors.RESET}")
    print(f" Confirmed IoC Pts: {current_score} pts ({len(confirmed_iocs)} / {TOTAL_IOCS_TO_FIND} target)")
    print()


def handle_ioc_list(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    target_iocs = state.iocs
    if args.status != "all":
        target_iocs = [i for i in state.iocs if i.status == args.status]
        
    if args.format == "json":
        print(json.dumps([dataclasses.asdict(i) for i in target_iocs], indent=2))
        return
        
    if args.format == "csv":
        print("ID,Type,Value,Technique,Tactic,Confidence,Status,Timestamp")
        for i in target_iocs:
            print(f"{i.id},{i.ioc_type},{i.value},{i.technique},{i.tactic},{i.confidence},{i.status},{i.timestamp}")
        return
        
    if args.format == "markdown":
        print("| ID | Type | Value | Technique | Tactic | Confidence | Status |")
        print("|---|---|---|---|---|---|---|")
        for i in target_iocs:
            print(f"| {i.id} | {i.ioc_type} | `{i.value}` | {i.technique} | {i.tactic} | {i.confidence} | {i.status} |")
        return
        
    # Default Table format
    print(f"{'ID':<10} | {'Type':<12} | {'Value':<30} | {'Technique':<10} | {'Status':<10}")
    print("-" * 80)
    for i in target_iocs:
        print(f"{i.id:<10} | {i.ioc_type:<12} | {i.value[:30]:<30} | {i.technique:<10} | {i.status:<10}")


def handle_check_rules(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    rules = [
        {
            "name": "IoC count within limits",
            "pass": len(state.iocs) <= MAX_IOC_SUBMISSIONS,
            "desc": f"Max {MAX_IOC_SUBMISSIONS} IoCs allowed."
        },
        {
            "name": "Report count within limits",
            "pass": len(state.reports) <= MAX_REPORT_SUBMISSIONS,
            "desc": f"Max {MAX_REPORT_SUBMISSIONS} Reports allowed."
        },
        {
            "name": "IoCs before report",
            "pass": len(state.reports) == 0 or len(state.iocs) > 0,
            "desc": "§10.4 You must submit at least one IoC before a report."
        },
        {
            "name": "No IoCs after accepted report",
            "pass": not state.ioc_submission_locked or (state.ioc_submission_locked and any(r.status == 'accepted' for r in state.reports)),
            "desc": "Locking strictly enforced after an accepted report."
        }
    ]
    
    all_passed = True
    print(f"\n{Colors.BOLD}=== RULE VALIDATION ==={Colors.RESET}")
    for rule in rules:
        if rule["pass"]:
            print(f" {Colors.GREEN}[PASS]{Colors.RESET} {rule['name']} - {rule['desc']}")
        else:
            print(f" {Colors.RED}[FAIL]{Colors.RESET} {rule['name']} - {rule['desc']}")
            all_passed = False
            
    if not all_passed:
        sys.exit(2)
        
    print(f"\n{Colors.GREEN}{Colors.BOLD}ALL RULES PASSED.{Colors.RESET}")


def handle_export(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    
    if args.format == "report_builder":
        export_data = {
            "team_name": state.team,
            "incident_id": state.incident_id,
            "export_time": get_now(),
            "confirmed_iocs": [dataclasses.asdict(i) for i in state.iocs if i.status == "confirmed"],
            "timeline": [dataclasses.asdict(a) for a in state.audit_log],
            "metadata": {
                "total_iocs_submitted": len(state.iocs),
                "total_reports_submitted": len(state.reports)
            }
        }
        print(json.dumps(export_data, indent=2))
    else:
        print(f"{Colors.RED}[!] Unsupported export format.{Colors.RESET}")
        sys.exit(1)


# ==========================================
# MAIN ROUTING
# ==========================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Cyberkent 4.0 Competition Submission Tracker")
    parser.add_argument("--state", default=os.path.expanduser("~/.cyberkent4_submissions.json"),
                        help="Path to the JSON state file.")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # init
    p_init = subparsers.add_parser("init", help="Initialize a new competition session")
    p_init.add_argument("--team", required=True, help="Team Name")
    p_init.add_argument("--incident-id", required=True, help="Incident ID")
    
    # add-ioc
    p_add_ioc = subparsers.add_parser("add-ioc", help="Record a submitted IoC")
    p_add_ioc.add_argument("--type", choices=['ip','hash','file','url','domain','email','user','service','tool','cmdline'], required=True)
    p_add_ioc.add_argument("--value", required=True, help="The IoC value")
    p_add_ioc.add_argument("--technique", required=True, help="MITRE ATT&CK technique (e.g. T1190)")
    p_add_ioc.add_argument("--tactic", required=True, help="MITRE ATT&CK tactic (e.g. TA0001)")
    p_add_ioc.add_argument("--confidence", choices=['high','medium','low'], required=True)
    p_add_ioc.add_argument("--notes", help="Optional notes")
    p_add_ioc.add_argument("--status", choices=['pending','confirmed','rejected'], default='pending')
    
    # update-ioc
    p_update_ioc = subparsers.add_parser("update-ioc", help="Update IoC status")
    p_update_ioc.add_argument("--id", required=True, help="IoC Submission ID")
    p_update_ioc.add_argument("--status", choices=['confirmed','rejected','pending'], required=True)
    
    # submit-report
    p_submit_report = subparsers.add_parser("submit-report", help="Record a report submission")
    p_submit_report.add_argument("--version", type=int, choices=[1,2,3], required=True)
    p_submit_report.add_argument("--notes", help="Optional notes")
    
    # update-report
    p_update_report = subparsers.add_parser("update-report", help="Update report status")
    p_update_report.add_argument("--version", type=int, required=True)
    p_update_report.add_argument("--status", choices=['accepted','review','rejected'], required=True)
    
    # status
    p_status = subparsers.add_parser("status", help="Display full competition state")
    
    # ioc-list
    p_ioc_list = subparsers.add_parser("ioc-list", help="Print IoC submission list")
    p_ioc_list.add_argument("--status", choices=['all','confirmed','pending','rejected'], default='confirmed')
    p_ioc_list.add_argument("--format", choices=['table','csv','json','markdown'], default='table')
    
    # check-rules
    p_check_rules = subparsers.add_parser("check-rules", help="Validate current state against rules")
    
    # export
    p_export = subparsers.add_parser("export", help="Export state")
    p_export.add_argument("--format", choices=['report_builder'], default='report_builder')
    
    args = parser.parse_args()
    
    handlers = {
        "init": handle_init,
        "add-ioc": handle_add_ioc,
        "update-ioc": handle_update_ioc,
        "submit-report": handle_submit_report,
        "update-report": handle_update_report,
        "status": handle_status,
        "ioc-list": handle_ioc_list,
        "check-rules": handle_check_rules,
        "export": handle_export
    }
    
    # Dispatch
    if args.command in handlers:
        handlers[args.command](args)

if __name__ == "__main__":
    main()
