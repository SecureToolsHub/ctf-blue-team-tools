#!/usr/bin/env python3
"""
net_map.py — Network discovery and ASCII topology mapper.

Scans a subnet for live hosts, probes common ports, and renders the
result as a simple ASCII tree using only: - _ + / \\ |

Usage:
    python3 net_map.py 192.168.1.0/24
    python3 net_map.py 192.168.1.0/24 --ports 22,80,443,445,3389
    python3 net_map.py 192.168.1.0/24 --timeout 0.5 --threads 100

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


def ping(host: str, timeout: float) -> bool:
    """Return True if host responds to a single ping."""
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


def render_tree(network_str: str, results: dict) -> str:
    """
    results: { ip: {"hostname": str, "ports": [int, ...]} }
    Draws an ASCII tree using only - _ + / \\ |
    """
    lines = []
    lines.append(f"+{'-' * (len(network_str) + 2)}+")
    lines.append(f"| {network_str} |")
    lines.append(f"+{'-' * (len(network_str) + 2)}+")

    ips = list(results.keys())
    for i, ip in enumerate(ips):
        is_last_host = (i == len(ips) - 1)
        host_prefix = "\\_" if is_last_host else "|_"
        info = results[ip]
        label = ip if not info["hostname"] else f"{ip} ({info['hostname']})"
        lines.append(f"  {host_prefix} {label}")

        cont = "   " if is_last_host else "|  "
        ports = info["ports"]
        if not ports:
            lines.append(f"  {cont}  \\_ no common ports open")
        else:
            for j, port in enumerate(ports):
                is_last_port = (j == len(ports) - 1)
                port_prefix = "\\_" if is_last_port else "|_"
                svc = COMMON_SERVICES.get(port, "?")
                lines.append(f"  {cont}  {port_prefix} {port}/tcp + {svc}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="ASCII network topology mapper")
    parser.add_argument("cidr", help="Target network, e.g. 192.168.1.0/24")
    parser.add_argument("--ports", default=None,
                         help="Comma-separated port list (default: common ports)")
    parser.add_argument("--timeout", type=float, default=0.6,
                         help="Per-probe timeout in seconds (default 0.6)")
    parser.add_argument("--threads", type=int, default=100,
                         help="Concurrent worker threads (default 100)")
    parser.add_argument("--no-resolve", action="store_true",
                         help="Skip reverse DNS lookups")
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

    tree = render_tree(str(network), results)
    print("\n" + tree)

    if args.output:
        with open(args.output, "w") as f:
            f.write(tree + "\n")
        print(f"\n[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
