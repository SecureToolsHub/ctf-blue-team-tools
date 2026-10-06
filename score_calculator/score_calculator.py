#!/usr/bin/env python3
"""
CTF Blue Team Score Calculator
Calculates scores according to standard competition regulations.
"""
import argparse
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional, List

# --- Constants & Config ---
MAX_IOC_SUBMISSIONS = 100
WARN_IOC_SUBMISSIONS = 90
MAX_REPORT_SUBMISSIONS = 3
WARN_REPORT_SUBMISSIONS = 2
MAX_IOCS = 20
IOC_POINT_VALUE = 100
DEFAULT_STATE_FILE = os.path.expanduser("~/.ctf_score_state.json")

# Colors
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Models ---
@dataclass
class Service:
    name: str
    task_points: int
    status: str = 'active'
    sla_pct: float = 100.0

@dataclass
class State:
    sla_points: float = 0.0
    ioc_found: int = 0
    ioc_submissions: int = 0
    report_submitted: bool = False
    report_submissions: int = 0
    k1: float = 0.6
    k2: float = 0.3
    k3: float = 0.1
    services: Dict[str, Service] = field(default_factory=dict)

    def to_json(self):
        d = asdict(self)
        return json.dumps(d, indent=4)
        
    @classmethod
    def from_json(cls, data: str):
        d = json.loads(data)
        services = d.pop('services', {})
        state = cls(**d)
        for k, v in services.items():
            state.services[k] = Service(**v)
        return state

def calculate_score(state: State) -> float:
    ioc_points = min(state.ioc_found, MAX_IOCS) * IOC_POINT_VALUE
    
    # Calculate SLA points if services exist, else use raw sla_points
    sla_score = state.sla_points
    if state.services:
        sla_score = sum((s.task_points * (s.sla_pct / 100.0)) for s in state.services.values())
        
    if state.report_submitted:
        report_score = ioc_points * (1.0 + state.k1 + state.k2 + state.k3)
    else:
        report_score = 0.0
        
    return sla_score + ioc_points + report_score

def print_score_breakdown(state: State):
    ioc_points = min(state.ioc_found, MAX_IOCS) * IOC_POINT_VALUE
    sla_score = state.sla_points
    if state.services:
        sla_score = sum((s.task_points * (s.sla_pct / 100.0)) for s in state.services.values())
        
    report_score = ioc_points * (1.0 + state.k1 + state.k2 + state.k3) if state.report_submitted else 0.0
    total = sla_score + ioc_points + report_score
    
    print(f"{Colors.BOLD}--- Score Breakdown ---{Colors.ENDC}")
    print(f"SLA Score:      {sla_score:.2f}")
    print(f"IoC Points:     {ioc_points:.2f} ({min(state.ioc_found, MAX_IOCS)} found, {state.ioc_submissions} submissions)")
    if state.report_submitted:
        print(f"Report Score:   {report_score:.2f} (K1={state.k1}, K2={state.k2}, K3={state.k3})")
    else:
        print(f"Report Score:   0.00 (Not submitted)")
    print(f"{Colors.OKGREEN}{Colors.BOLD}Total U Score:  {total:.2f}{Colors.ENDC}")

# --- CLI Commands ---

def cmd_calc(args):
    state = State(
        sla_points=args.sla_points,
        ioc_found=args.ioc_found,
        ioc_submissions=args.ioc_submitted,
        report_submitted=args.report_submitted,
        k1=args.k1,
        k2=args.k2,
        k3=args.k3
    )
    print_score_breakdown(state)

def cmd_simulate(args):
    # Current
    s_curr = State(sla_points=args.sla_points, ioc_found=args.ioc_found, report_submitted=args.report_submitted)
    curr_score = calculate_score(s_curr)
    
    # All 20 IoCs
    s_20 = State(sla_points=args.sla_points, ioc_found=20, report_submitted=args.report_submitted)
    
    # 100% SLA (assuming given sla_points is max)
    # If no services, we just double sla? Let's just say "SLA maintained" uses args.sla_points
    
    # Report accepted with max coefficients
    s_rep = State(sla_points=args.sla_points, ioc_found=args.ioc_found, report_submitted=True, k1=0.6, k2=0.3, k3=0.1)
    
    # Best possible score (assume SLA max = max(args.sla_points, 1500), 20 IoCs, report max)
    s_best = State(sla_points=max(args.sla_points, 1500.0), ioc_found=20, report_submitted=True, k1=0.6, k2=0.3, k3=0.1)
    
    print(f"{Colors.BOLD}--- What-If Simulation ---{Colors.ENDC}")
    scenarios = [
        ("Current State", calculate_score(s_curr)),
        ("If all 20 IoCs found", calculate_score(s_20)),
        ("If report accepted (max coeffs)", calculate_score(s_rep)),
        ("Best possible score", calculate_score(s_best))
    ]
    
    for name, score in scenarios:
        delta = score - curr_score
        delta_str = f"(+{delta:.2f})" if delta > 0 else ""
        print(f"{name.ljust(35)} {Colors.OKCYAN}{score:8.2f}{Colors.ENDC} {Colors.OKGREEN}{delta_str}{Colors.ENDC}")

def cmd_sla_calc(args):
    if args.list_services:
        print("Pre-defined service estimation (300 to 1500):")
        print("- WebApp: 1500")
        print("- Database: 1000")
        print("- AD: 1000")
        print("- Custom: 300")
        return
        
    pts = args.task_points * (args.sla_pct / 100.0)
    print(f"Service {args.service} with {args.task_points} max points at {args.sla_pct}%:")
    print(f"Earned: {pts:.2f} points")

def load_state(path: str) -> State:
    if os.path.exists(path):
        with open(path, 'r') as f:
            return State.from_json(f.read())
    return State()

def save_state(state: State, path: str):
    with open(path, 'w') as f:
        f.write(state.to_json())

def cmd_track(args):
    state = load_state(args.state)
    dirty = False
    
    if args.add_ioc:
        if state.ioc_submissions >= MAX_IOC_SUBMISSIONS:
            print(f"{Colors.FAIL}ERROR: Maximum IoC submissions ({MAX_IOC_SUBMISSIONS}) reached!{Colors.ENDC}")
            sys.exit(1)
            
        state.ioc_submissions += 1
        state.ioc_found += 1
        dirty = True
        print(f"{Colors.OKGREEN}Recorded IoC '{args.add_ioc}'. Total found: {state.ioc_found}, Submissions: {state.ioc_submissions}{Colors.ENDC}")
        
        if state.ioc_submissions >= WARN_IOC_SUBMISSIONS:
            print(f"{Colors.WARNING}WARNING: IoC submissions approaching limit ({state.ioc_submissions}/{MAX_IOC_SUBMISSIONS}){Colors.ENDC}")
            
    if args.submit_report:
        if state.ioc_submissions == 0:
            print(f"{Colors.FAIL}ERROR: Cannot submit report before submitting IoCs (hard rule §10.4).{Colors.ENDC}")
            sys.exit(1)
            
        if state.report_submissions >= MAX_REPORT_SUBMISSIONS:
            print(f"{Colors.FAIL}ERROR: Maximum report submissions ({MAX_REPORT_SUBMISSIONS}) reached!{Colors.ENDC}")
            sys.exit(1)
            
        state.report_submissions += 1
        state.report_submitted = True
        dirty = True
        print(f"{Colors.OKGREEN}Recorded Report version '{args.submit_report}'. Submissions: {state.report_submissions}{Colors.ENDC}")
        
        if state.report_submissions >= WARN_REPORT_SUBMISSIONS:
            print(f"{Colors.WARNING}WARNING: Report submissions approaching limit ({state.report_submissions}/{MAX_REPORT_SUBMISSIONS}){Colors.ENDC}")
            
    if args.update_sla:
        service_name, status = args.update_sla
        if service_name not in state.services:
            state.services[service_name] = Service(name=service_name, task_points=1000)
            
        state.services[service_name].status = status
        
        # Adjust pct based on status mapping
        pct_map = {'active': 100.0, 'degraded': 50.0, 'vulnerable': 20.0, 'off': 0.0}
        if status in pct_map:
            state.services[service_name].sla_pct = pct_map[status]
            
        dirty = True
        print(f"{Colors.OKGREEN}Updated SLA for {service_name} to {status} ({state.services[service_name].sla_pct}%){Colors.ENDC}")
        
    if dirty:
        save_state(state, args.state)
        
    if args.show or not dirty:
        print_score_breakdown(state)

def cmd_dashboard(args):
    state = load_state(args.state)
    
    print(f"{Colors.BOLD}{Colors.HEADER}========================================={Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}        CTF Status Dashboard             {Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}========================================={Colors.ENDC}")
    print("")
    
    # SLA Status
    print(f"{Colors.BOLD}SLA Status:{Colors.ENDC}")
    if not state.services:
        print("  No services tracked.")
    for name, srv in state.services.items():
        color = Colors.OKGREEN if srv.status == 'active' else (Colors.WARNING if srv.status == 'degraded' else Colors.FAIL)
        print(f"  - {name.ljust(15)}: {color}{srv.status.upper().ljust(10)} {srv.sla_pct}%{Colors.ENDC}")
        
    print("")
    # Submissions
    print(f"{Colors.BOLD}Submissions:{Colors.ENDC}")
    ioc_color = Colors.OKGREEN if state.ioc_submissions < WARN_IOC_SUBMISSIONS else Colors.WARNING
    print(f"  IoC Submissions: {ioc_color}{state.ioc_submissions} / {MAX_IOC_SUBMISSIONS}{Colors.ENDC}")
    print(f"  IoCs Confirmed:  {Colors.OKCYAN}{state.ioc_found} / {MAX_IOCS}{Colors.ENDC}")
    
    rep_color = Colors.OKGREEN if state.report_submissions < WARN_REPORT_SUBMISSIONS else Colors.WARNING
    print(f"  Reports:         {rep_color}{state.report_submissions} / {MAX_REPORT_SUBMISSIONS}{Colors.ENDC}")
    
    print("")
    print_score_breakdown(state)

def main():
    parser = argparse.ArgumentParser(description="CTF Blue Team Score Calculator")
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # calc
    p_calc = subparsers.add_parser("calc", help="Calculate current score")
    p_calc.add_argument("--sla-points", type=float, default=0.0)
    p_calc.add_argument("--ioc-found", type=int, default=0)
    p_calc.add_argument("--ioc-submitted", type=int, default=0)
    p_calc.add_argument("--report-submitted", action="store_true")
    p_calc.add_argument("--k1", type=float, default=0.6)
    p_calc.add_argument("--k2", type=float, default=0.3)
    p_calc.add_argument("--k3", type=float, default=0.1)
    
    # simulate
    p_sim = subparsers.add_parser("simulate", help="What-if analysis")
    p_sim.add_argument("--sla-points", type=float, default=0.0)
    p_sim.add_argument("--ioc-found", type=int, default=0)
    p_sim.add_argument("--report-submitted", action="store_true")
    
    # sla-calc
    p_sla = subparsers.add_parser("sla-calc", help="SLA points calculator")
    p_sla.add_argument("--service", type=str, default="Unknown")
    p_sla.add_argument("--task-points", type=int, default=1000)
    p_sla.add_argument("--status", type=str, choices=['active', 'degraded', 'vulnerable', 'off'], default='active')
    p_sla.add_argument("--sla-pct", type=float, default=100.0)
    p_sla.add_argument("--list-services", action="store_true")
    
    # track
    p_track = subparsers.add_parser("track", help="Interactive session tracker")
    p_track.add_argument("--state", type=str, default=DEFAULT_STATE_FILE)
    p_track.add_argument("--add-ioc", type=str, metavar="VALUE")
    p_track.add_argument("--submit-report", type=str, metavar="VERSION")
    p_track.add_argument("--update-sla", nargs=2, metavar=("SERVICE", "STATUS"))
    p_track.add_argument("--show", action="store_true")
    
    # dashboard
    p_dash = subparsers.add_parser("dashboard", help="Print dashboard")
    p_dash.add_argument("--state", type=str, default=DEFAULT_STATE_FILE)
    
    args = parser.parse_args()
    
    if args.command == "calc":
        cmd_calc(args)
    elif args.command == "simulate":
        cmd_simulate(args)
    elif args.command == "sla-calc":
        cmd_sla_calc(args)
    elif args.command == "track":
        cmd_track(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)

if __name__ == "__main__":
    main()
