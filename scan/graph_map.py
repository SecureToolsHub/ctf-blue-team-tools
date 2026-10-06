#!/usr/bin/env python3
"""
graph_map.py — Network structural diagram (graph layout, not a tree).

Scans a subnet like net_map.py, but renders the result as a
hub-and-spoke ASCII schematic: a central network node connected via
a bus line to boxed host nodes. Uses only: - _ + / \\ |

Usage:
    python3 graph_map.py 192.168.1.0/24
    python3 graph_map.py 192.168.1.0/24 --ports 22,80,443 --per-row 5
    python3 graph_map.py 192.168.1.0/24 -o schematic.txt

Only scan networks/hosts you are authorized to test.
"""

import argparse
import ipaddress
import socket
import subprocess
import sys
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
                  445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgres", 5900: "vnc", 8080: "http-alt",
}


# ---------- scanning (same approach as net_map.py) ----------

def ping(host: str, timeout: float) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), host]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False


def scan_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def discover_hosts(network: ipaddress.IPv4Network, timeout: float, threads: int):
    live = []
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(ping, str(h), timeout): str(h) for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                if fut.result():
                    live.append(host)
            except Exception:
                pass
    return sorted(live, key=lambda ip: tuple(int(p) for p in ip.split(".")))


def scan_host_ports(host: str, ports, timeout: float, threads: int):
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = {pool.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            p = futures[fut]
            try:
                if fut.result():
                    open_ports.append(p)
            except Exception:
                pass
    return sorted(open_ports)


# ---------- box / graph rendering ----------

def make_box(content_lines, min_width=16):
    """Return list of strings forming a bordered box around content_lines."""
    width = max(min_width, max(len(s) for s in content_lines) + 2)
    top = "+" + "-" * width + "+"
    bottom = top
    body = []
    for line in content_lines:
        body.append("|" + line.center(width) + "|")
    return [top] + body, width + 2  # +2 for the two border chars


def pad_box(box_lines, height):
    """Pad a box's line list to a fixed height (adds blank interior lines)."""
    if len(box_lines) >= height:
        return box_lines
    width = len(box_lines[0])
    bottom = box_lines[-1]
    filler = "|" + " " * (width - 2) + "|"
    return box_lines[:-1] + [filler] * (height - len(box_lines)) + [bottom]


def host_box_content(ip, hostname, ports):
    lines = [ip]
    if hostname:
        lines.append(hostname[:18])
    if ports:
        shown = ",".join(str(p) for p in ports[:4])
        if len(ports) > 4:
            shown += "..."
        lines.append(shown)
    else:
        lines.append("no open ports")
    return lines


def render_star(network_str, results, per_row=4):
    """
    results: { ip: {"hostname": str, "ports": [int,...]} } (ordered)
    Draws a hub-and-spoke schematic using only - _ + / \\ |
    """
    ips = list(results.keys())
    if not ips:
        return f"+{'-'*20}+\n|{network_str.center(20)}|\n+{'-'*20}+\n   (no live hosts)"

    out_blocks = []
    for row_start in range(0, len(ips), per_row):
        row_ips = ips[row_start: row_start + per_row]

        boxes = []
        widths = []
        for ip in row_ips:
            info = results[ip]
            content = host_box_content(ip, info["hostname"], info["ports"])
            box, w = make_box(content, min_width=16)
            boxes.append(box)
            widths.append(w)

        height = max(len(b) for b in boxes)
        boxes = [pad_box(b, height) for b in boxes]

        gap = 3
        centers = []
        pos = 0
        for w in widths:
            centers.append(pos + w // 2)
            pos += w + gap
        total_width = pos - gap

        # bus line with '+' junctions at each host center
        bus = list("-" * total_width)
        for c in centers:
            if 0 <= c < total_width:
                bus[c] = "+"
        bus_line = "".join(bus)

        # vertical connector row (all '|' under junctions)
        vert = [" "] * total_width
        for c in centers:
            vert[c] = "|"
        vert_line = "".join(vert)

        # assemble host boxes side by side
        row_lines = []
        for line_idx in range(height):
            parts = []
            for b in boxes:
                parts.append(b[line_idx])
            row_lines.append((" " * gap).join(parts))

        block = [vert_line, bus_line, vert_line] + row_lines
        out_blocks.append("\n".join(block))

    # gateway box centered over the first row's bus width
    first_ips = ips[:per_row]
    first_widths = []
    for ip in first_ips:
        info = results[ip]
        content = host_box_content(ip, info["hostname"], info["ports"])
        _, w = make_box(content, min_width=16)
        first_widths.append(w)
    total_first = sum(first_widths) + 3 * (len(first_widths) - 1)

    gw_box, gw_w = make_box(["NETWORK", network_str], min_width=16)
    left_pad = max(0, (total_first - gw_w) // 2)
    gw_lines = [(" " * left_pad) + ln for ln in gw_box]
    gw_connector = " " * (left_pad + gw_w // 2) + "|"

    final = "\n".join(gw_lines) + "\n" + gw_connector + "\n" + "\n\n".join(out_blocks)
    return final


def main():
    parser = argparse.ArgumentParser(description="ASCII network graph/structural diagram")
    parser.add_argument("cidr", help="Target network, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", default=None,
                         help="Comma-separated port list (default: common ports)")
    parser.add_argument("--timeout", type=float, default=0.6)
    parser.add_argument("--threads", type=int, default=100)
    parser.add_argument("--per-row", type=int, default=4,
                         help="Host boxes per row in the diagram (default 4)")
    parser.add_argument("--no-resolve", action="store_true")
    parser.add_argument("-o", "--output", help="Write result to file")
    args = parser.parse_args()

    try:
        network = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as e:
        print(f"Invalid network: {e}", file=sys.stderr)
        sys.exit(1)

    ports = DEFAULT_PORTS
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]

    print(f"[+] Discovering live hosts on {network} ...")
    live_hosts = discover_hosts(network, args.timeout, args.threads)
    print(f"[+] {len(live_hosts)} host(s) up")

    results = {}
    for idx, ip in enumerate(live_hosts, 1):
        print(f"[+] ({idx}/{len(live_hosts)}) scanning {ip} ...")
        hostname = "" if args.no_resolve else resolve_hostname(ip)
        open_ports = scan_host_ports(ip, ports, args.timeout, args.threads)
        results[ip] = {"hostname": hostname, "ports": open_ports}

    diagram = render_star(str(network), results, per_row=args.per_row)
    print("\n" + diagram)

    if args.output:
        with open(args.output, "w") as f:
            f.write(diagram + "\n")
        print(f"\n[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
