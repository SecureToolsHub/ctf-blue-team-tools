#!/usr/bin/env python3
"""
proc_tree.py — Host process tree and connection graph visualizer.

Renders running processes as a parent/child ASCII tree, and (with
sufficient privileges) attaches each process's active network
connections. Uses only: - _ + / \\ |

Requires: psutil  (pip install psutil)

Usage:
    python3 proc_tree.py                 # full tree
    python3 proc_tree.py --pid 1234      # subtree rooted at PID
    python3 proc_tree.py --conns-only    # only show processes with connections
    python3 proc_tree.py -o proc_tree.txt
"""

import argparse
import sys

try:
    import psutil
except ImportError:
    print("This tool requires psutil: pip install psutil", file=sys.stderr)
    sys.exit(1)


def get_connections(proc) -> list:
    try:
        conns = proc.net_connections(kind="inet")
    except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
        try:
            conns = proc.connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []
    out = []
    for c in conns:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
        out.append(f"{c.status} {laddr} -> {raddr}")
    return out


def build_tree():
    """Return dict: pid -> {info, children: [pid,...]}"""
    nodes = {}
    for p in psutil.process_iter(["pid", "ppid", "name", "username", "exe"]):
        try:
            info = p.info
            nodes[info["pid"]] = {
                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": info["name"] or "?",
                "user": info["username"] or "?",
                "children": [],
                "proc": p,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    roots = []
    for pid, node in nodes.items():
        ppid = node["ppid"]
        if ppid in nodes and ppid != pid:
            nodes[ppid]["children"].append(pid)
        else:
            roots.append(pid)
    return nodes, roots


def render(nodes, pid, prefix="", is_last=True, lines=None,
           show_conns=True, conns_only=False):
    if lines is None:
        lines = []

    node = nodes[pid]
    branch = "\\_" if is_last else "|_"
    header = f"{prefix}{branch} [{node['pid']}] {node['name']} (user: {node['user']})"

    conns = get_connections(node["proc"]) if show_conns else []

    if conns_only and not conns and not any(
        _has_conns_in_subtree(nodes, c) for c in node["children"]
    ):
        pass  # skip printing this line, but still recurse for children with conns
    else:
        lines.append(header)
        child_prefix = prefix + ("   " if is_last else "|  ")
        for i, ln in enumerate(conns):
            is_last_conn = (i == len(conns) - 1) and not node["children"]
            conn_branch = "\\_" if is_last_conn else "|_"
            lines.append(f"{child_prefix}{conn_branch} + {ln}")

    children = sorted(node["children"], key=lambda c: nodes[c]["name"])
    child_prefix = prefix + ("   " if is_last else "|  ")
    for i, child_pid in enumerate(children):
        is_last_child = (i == len(children) - 1)
        render(nodes, child_pid, child_prefix, is_last_child, lines,
               show_conns, conns_only)

    return lines


def _has_conns_in_subtree(nodes, pid) -> bool:
    node = nodes[pid]
    if get_connections(node["proc"]):
        return True
    return any(_has_conns_in_subtree(nodes, c) for c in node["children"])


def main():
    parser = argparse.ArgumentParser(description="ASCII process tree + connection graph")
    parser.add_argument("--pid", type=int, default=None,
                         help="Root the tree at this PID instead of all roots")
    parser.add_argument("--no-conns", action="store_true",
                         help="Skip network connection lookup (faster, no perms needed)")
    parser.add_argument("--conns-only", action="store_true",
                         help="Only show processes that have (or lead to) connections")
    parser.add_argument("-o", "--output", help="Write result to file")
    args = parser.parse_args()

    nodes, roots = build_tree()
    show_conns = not args.no_conns

    all_lines = []
    if args.pid is not None:
        if args.pid not in nodes:
            print(f"PID {args.pid} not found", file=sys.stderr)
            sys.exit(1)
        all_lines = render(nodes, args.pid, "", True, None,
                            show_conns, args.conns_only)
    else:
        roots = sorted(roots, key=lambda p: nodes[p]["name"])
        for i, r in enumerate(roots):
            all_lines.extend(
                render(nodes, r, "", i == len(roots) - 1, None,
                       show_conns, args.conns_only)
            )

    header = f"+{'-' * 30}+\n| HOST PROCESS TREE ({len(nodes)} procs) |\n+{'-' * 30}+"
    output = header + "\n" + "\n".join(all_lines)
    print(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output + "\n")
        print(f"\n[+] Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
