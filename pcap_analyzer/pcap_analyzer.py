#!/usr/bin/env python3
"""
pcap_analyzer.py — PCAP/pcapng network traffic analysis for Blue Team CTF.

Uses scapy for deep packet inspection and wraps tshark for fast bulk operations.
No Wireshark required — runs entirely from the command line.

Subcommands:
  summary     Quick overview: protocols, top IPs, packet counts
  creds       Extract cleartext credentials (HTTP Basic, FTP, SMTP, Telnet, POP3)
  dns         Extract all DNS queries and responses
  http        Reconstruct HTTP requests/responses, find flags and IOCs
  streams     List TCP streams; optionally dump a specific stream as ASCII
  beacon      Detect periodic C2 beaconing (regular-interval connections)
  ioc         Extract IPs, domains, URLs, hashes from all payload text
  files       Carve transferred files from HTTP sessions (GET responses)
  export      Export raw packet bytes for a filter to a new pcap

Usage:
    python3 pcap_analyzer.py summary     capture.pcap
    python3 pcap_analyzer.py creds       capture.pcap
    python3 pcap_analyzer.py dns         capture.pcap --filter-type A
    python3 pcap_analyzer.py http        capture.pcap --flag-pattern 'ctf\\{[^}]+\\}'
    python3 pcap_analyzer.py streams     capture.pcap
    python3 pcap_analyzer.py streams     capture.pcap --stream-id 3
    python3 pcap_analyzer.py beacon      capture.pcap --min-count 5 --max-jitter 5
    python3 pcap_analyzer.py ioc         capture.pcap -o iocs.txt
    python3 pcap_analyzer.py files       capture.pcap --out-dir ./carved/
    python3 pcap_analyzer.py export      capture.pcap --bpf "host 1.2.3.4" -o filtered.pcap
"""

import argparse
import base64
import collections
import io
import ipaddress
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
from datetime import datetime

# ---------------------------------------------------------------------------
# Optional imports — degrade gracefully
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        rdpcap, PcapReader, IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR,
        Raw, Ether, wrpcap
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

FLAG_PATTERN_DEFAULT = r"(?:ctf|flag|FLAG|CTF|HTB|cyberkent|CKT)\{[^\}]{1,200}\}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok(msg):  print(f"\033[92m[+]\033[0m {msg}")
def warn(msg): print(f"\033[93m[!]\033[0m {msg}")
def fail(msg): print(f"\033[91m[-]\033[0m {msg}")
def info(msg): print(f"\033[94m[~]\033[0m {msg}")
def hdr(msg):  print(f"\n\033[1m{'─'*60}\n  {msg}\n{'─'*60}\033[0m")


def require_scapy():
    if not HAS_SCAPY:
        fail("scapy not installed. Run: pip install scapy")
        sys.exit(1)


def require_tshark():
    if not _tshark_available():
        fail("tshark not found. Install: apt install tshark")
        sys.exit(1)


def _tshark_available():
    import shutil
    return shutil.which("tshark") is not None


def is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETS)
    except ValueError:
        return False


def load_pcap(path):
    """Load a pcap, trying scapy first, then tshark-converted tmp file."""
    require_scapy()
    try:
        info(f"Loading {path} ...")
        pkts = rdpcap(path)
        ok(f"Loaded {len(pkts)} packets")
        return pkts
    except Exception as e:
        fail(f"scapy rdpcap failed: {e}")
        sys.exit(1)


def stream_pcap(path):
    """Generator: yield packets one at a time (memory-efficient for large files)."""
    require_scapy()
    with PcapReader(path) as reader:
        for pkt in reader:
            yield pkt


def get_payload(pkt):
    """Return the Raw layer bytes, or b''."""
    if pkt.haslayer(Raw):
        return bytes(pkt[Raw])
    return b""


def safe_ascii(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def extract_ips(pkt):
    src, dst = None, None
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    return src, dst


# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------

def tshark_run(path, fields, display_filter=None, extra_args=None):
    """
    Run tshark with -T fields and return list of field-value tuples.
    """
    cmd = ["tshark", "-r", path, "-T", "fields", "-E", "separator=|"]
    for f in fields:
        cmd += ["-e", f]
    if display_filter:
        cmd += ["-Y", display_filter]
    if extra_args:
        cmd += extra_args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        rows = []
        for line in r.stdout.splitlines():
            parts = line.split("|")
            rows.append(parts)
        return rows
    except subprocess.TimeoutExpired:
        fail("tshark timed out")
        return []
    except FileNotFoundError:
        fail("tshark not found")
        return []


# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------

def cmd_summary(args):
    require_scapy()
    hdr("PCAP SUMMARY")
    info(f"File: {args.pcap}  ({os.path.getsize(args.pcap):,} bytes)")

    proto_count = collections.Counter()
    src_count   = collections.Counter()
    dst_count   = collections.Counter()
    port_count  = collections.Counter()
    total       = 0
    first_ts    = None
    last_ts     = None

    for pkt in stream_pcap(args.pcap):
        total += 1
        ts = float(pkt.time)
        if first_ts is None or ts < first_ts:
            first_ts = ts
        if last_ts is None or ts > last_ts:
            last_ts = ts

        src, dst = extract_ips(pkt)
        if src:
            src_count[src] += 1
        if dst:
            dst_count[dst] += 1

        if pkt.haslayer(TCP):
            proto_count["TCP"] += 1
            port_count[pkt[TCP].dport] += 1
        elif pkt.haslayer(UDP):
            proto_count["UDP"] += 1
            port_count[pkt[UDP].dport] += 1
        elif pkt.haslayer(IP):
            proto_count[f"IP/{pkt[IP].proto}"] += 1
        else:
            proto_count["OTHER"] += 1

        if pkt.haslayer(DNS):
            proto_count["DNS"] += 1

    duration = (last_ts - first_ts) if first_ts and last_ts else 0

    ok(f"Total packets : {total:,}")
    ok(f"Time span     : {duration:.1f}s  "
       f"({datetime.fromtimestamp(first_ts).strftime('%Y-%m-%d %H:%M:%S') if first_ts else '?'} "
       f"→ {datetime.fromtimestamp(last_ts).strftime('%Y-%m-%d %H:%M:%S') if last_ts else '?'})")

    print("\n── Protocol breakdown ──")
    for proto, cnt in proto_count.most_common():
        bar = "█" * min(40, int(cnt * 40 / max(proto_count.values())))
        print(f"  {proto:<12} {cnt:>7,}  {bar}")

    print(f"\n── Top 10 source IPs ──")
    for ip, cnt in src_count.most_common(10):
        priv = " (private)" if is_private(ip) else ""
        print(f"  {ip:<20} {cnt:>6,} pkts{priv}")

    print(f"\n── Top 10 destination IPs ──")
    for ip, cnt in dst_count.most_common(10):
        priv = " (private)" if is_private(ip) else ""
        print(f"  {ip:<20} {cnt:>6,} pkts{priv}")

    print(f"\n── Top 15 destination ports ──")
    for port, cnt in port_count.most_common(15):
        svc = _port_svc(port)
        print(f"  :{port:<6} {cnt:>6,}  {svc}")


def _port_svc(port):
    m = {20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",
         80:"http",110:"pop3",143:"imap",443:"https",445:"smb",
         587:"smtp-sub",993:"imaps",995:"pop3s",3306:"mysql",3389:"rdp",
         5432:"postgres",6379:"redis",8080:"http-alt",8443:"https-alt",
         9200:"elasticsearch",5601:"kibana",8000:"splunk-web"}
    return m.get(port, "")


# ---------------------------------------------------------------------------
# CREDENTIALS
# ---------------------------------------------------------------------------

HTTP_BASIC_RE  = re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
HTTP_FORM_RE   = re.compile(rb"(?:username|user|login|email|pass(?:word)?)[=:]([^\s&\r\n]{1,64})",
                             re.IGNORECASE)
FTP_USER_RE    = re.compile(rb"USER ([^\r\n]+)", re.IGNORECASE)
FTP_PASS_RE    = re.compile(rb"PASS ([^\r\n]+)", re.IGNORECASE)
SMTP_AUTH_RE   = re.compile(rb"AUTH LOGIN|AUTH PLAIN|334 |235 ", re.IGNORECASE)
POP3_USER_RE   = re.compile(rb"\+OK|USER ([^\r\n]+)|PASS ([^\r\n]+)", re.IGNORECASE)
TELNET_CRED_RE = re.compile(rb"(?:login|password):\s*([^\r\n\x00]{1,64})", re.IGNORECASE)
HTTP_HOST_RE   = re.compile(rb"Host:\s*([^\r\n]+)", re.IGNORECASE)


def cmd_creds(args):
    require_scapy()
    hdr("CLEARTEXT CREDENTIAL EXTRACTION")

    findings = []
    stream_data = collections.defaultdict(bytes)

    for pkt in stream_pcap(args.pcap):
        payload = get_payload(pkt)
        if not payload:
            continue

        src, dst = extract_ips(pkt)
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)

        # Accumulate TCP stream data per 5-tuple for SMTP/FTP multi-packet
        if pkt.haslayer(TCP) and src and dst:
            key = (src, pkt[TCP].sport, dst, dport)
            stream_data[key] += payload

        # HTTP Basic Auth
        for m in HTTP_BASIC_RE.finditer(payload):
            try:
                decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
                host_m = HTTP_HOST_RE.search(payload)
                host = host_m.group(1).decode("utf-8", errors="replace").strip() if host_m else dst
                findings.append(("HTTP Basic", src, dst, dport,
                                  f"host={host}  credentials={decoded!r}"))
            except Exception:
                pass

        # HTTP form POST credentials
        if b"POST" in payload[:10] or b"username=" in payload or b"password=" in payload:
            for m in HTTP_FORM_RE.finditer(payload):
                findings.append(("HTTP Form", src, dst, dport,
                                  safe_ascii(payload[:120]).replace("\n", " ").strip()))
                break

        # FTP
        if dport == 21 or (pkt.haslayer(TCP) and pkt[TCP].sport == 21):
            for m in FTP_USER_RE.finditer(payload):
                findings.append(("FTP USER", src, dst, dport,
                                  m.group(1).decode("utf-8", errors="replace").strip()))
            for m in FTP_PASS_RE.finditer(payload):
                findings.append(("FTP PASS", src, dst, dport,
                                  m.group(1).decode("utf-8", errors="replace").strip()))

        # Telnet
        if dport == 23 or (pkt.haslayer(TCP) and pkt[TCP].sport == 23):
            for m in TELNET_CRED_RE.finditer(payload):
                findings.append(("Telnet", src, dst, dport,
                                  m.group(1).decode("utf-8", errors="replace").strip()))

        # POP3
        if dport == 110:
            for m in POP3_USER_RE.finditer(payload):
                if m.group(1):
                    findings.append(("POP3 USER", src, dst, dport,
                                      m.group(1).decode("utf-8", errors="replace").strip()))
                if m.group(2):
                    findings.append(("POP3 PASS", src, dst, dport,
                                      m.group(2).decode("utf-8", errors="replace").strip()))

    if not findings:
        warn("No cleartext credentials found in this capture.")
    else:
        ok(f"{len(findings)} credential hit(s):\n")
        for proto, src, dst, dport, detail in findings:
            print(f"  [{proto:<12}] {src} → {dst}:{dport}")
            print(f"    {detail}\n")

    if args.output:
        with open(args.output, "w") as f:
            for row in findings:
                f.write("\t".join(str(x) for x in row) + "\n")
        ok(f"Saved to {args.output}")


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def cmd_dns(args):
    require_scapy()
    hdr("DNS ANALYSIS")

    queries   = collections.Counter()
    responses = collections.defaultdict(list)
    requesters = collections.defaultdict(set)

    for pkt in stream_pcap(args.pcap):
        if not pkt.haslayer(DNS):
            continue
        src, dst = extract_ips(pkt)
        dns = pkt[DNS]

        # Query
        if dns.qr == 0 and dns.qdcount > 0:
            try:
                q = dns[DNSQR]
                qname = q.qname.decode("utf-8", errors="replace").rstrip(".")
                qtype = q.qtype
                if args.filter_type and args.filter_type.upper() != _qtype_str(qtype):
                    continue
                queries[(qname, _qtype_str(qtype))] += 1
                if src:
                    requesters[qname].add(src)
            except Exception:
                pass

        # Response
        if dns.qr == 1 and dns.ancount > 0:
            try:
                qname = dns[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                rr = dns[DNSRR]
                while rr:
                    try:
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="replace")
                        responses[qname].append(str(rdata))
                    except Exception:
                        pass
                    rr = rr.payload if hasattr(rr.payload, "rdata") else None
            except Exception:
                pass

    ok(f"{sum(queries.values())} DNS queries, {len(responses)} unique names with responses")

    print(f"\n── Top queried domains ──")
    for (name, qtype), cnt in queries.most_common(30):
        resolved = ", ".join(set(responses.get(name, [])))[:60]
        req_ips = ", ".join(sorted(requesters[name]))[:40]
        long_flag = "  ← LONG (possible exfil)" if len(name) > 50 else ""
        print(f"  {cnt:>4}x  [{qtype}]  {name}{long_flag}")
        if resolved:
            print(f"         → {resolved}")
        if req_ips:
            print(f"         requesters: {req_ips}")

    # Long subdomain alert
    long_names = [(n, t) for (n, t), c in queries.items() if len(n) > 50]
    if long_names:
        print(f"\n── ⚠️  Suspicious long subdomains ({len(long_names)}) — possible DNS exfil ──")
        for name, qtype in long_names[:20]:
            print(f"  [{qtype}] {name}")


def _qtype_str(q):
    m = {1:"A",2:"NS",5:"CNAME",6:"SOA",12:"PTR",15:"MX",16:"TXT",28:"AAAA",33:"SRV",255:"ANY"}
    return m.get(q, str(q))


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def cmd_http(args):
    hdr("HTTP ANALYSIS")
    flag_re = re.compile(args.flag_pattern.encode(), re.IGNORECASE) if args.flag_pattern else None

    if _tshark_available():
        _http_via_tshark(args, flag_re)
    else:
        _http_via_scapy(args, flag_re)


def _http_via_tshark(args, flag_re):
    info("Using tshark for HTTP extraction")

    rows = tshark_run(args.pcap,
                       ["ip.src", "ip.dst", "tcp.dstport",
                        "http.request.method", "http.request.uri",
                        "http.host", "http.response.code",
                        "http.content_length"],
                       display_filter="http")

    print(f"\n── HTTP Requests/Responses ──")
    found_flags = []
    for row in rows[:200]:
        if len(row) < 8:
            continue
        src, dst, port, method, uri, host, code, clen = (row + [""] * 8)[:8]
        if method:
            line = f"  {src} → {host or dst}:{port}  {method} {uri}"
            print(line)
        elif code:
            print(f"  ← {code}  ({clen} bytes)")

    # Flag hunt in HTTP payloads via tshark follow
    if flag_re:
        print(f"\n── Flag pattern hunt in HTTP ──")
        streams = tshark_run(args.pcap, ["tcp.stream"],
                              display_filter="http", extra_args=["-T", "fields"])
        stream_ids = set(r[0] for r in streams if r and r[0].isdigit())
        for sid in sorted(stream_ids, key=int)[:20]:
            try:
                r = subprocess.run(
                    ["tshark", "-r", args.pcap, "-q",
                     "--follow", f"TCP,ascii,{sid}"],
                    capture_output=True, timeout=10
                )
                data = r.stdout
                for m in flag_re.finditer(data):
                    flag = m.group(0).decode("utf-8", errors="replace")
                    ok(f"FLAG in TCP stream {sid}: {flag}")
                    found_flags.append(flag)
            except Exception:
                pass
        if not found_flags:
            info("No flags found matching pattern in HTTP streams")


def _http_via_scapy(args, flag_re):
    require_scapy()
    info("Using scapy for HTTP extraction (tshark not available)")
    for pkt in stream_pcap(args.pcap):
        payload = get_payload(pkt)
        if not payload or b"HTTP" not in payload[:20]:
            continue
        src, dst = extract_ips(pkt)
        text = safe_ascii(payload[:2048])
        print(f"  {src} → {dst}: {text[:120].replace(chr(10), ' ')}")
        if flag_re:
            for m in flag_re.finditer(payload):
                ok(f"FLAG: {m.group(0).decode('utf-8', errors='replace')}")


# ---------------------------------------------------------------------------
# TCP STREAMS
# ---------------------------------------------------------------------------

def cmd_streams(args):
    hdr("TCP STREAMS")

    if not _tshark_available():
        fail("tshark required for stream reconstruction")
        sys.exit(1)

    if args.stream_id is not None:
        # Follow a specific stream
        info(f"Dumping TCP stream {args.stream_id}:")
        r = subprocess.run(
            ["tshark", "-r", args.pcap, "-q",
             "--follow", f"TCP,ascii,{args.stream_id}"],
            capture_output=True, text=True, timeout=30
        )
        print(r.stdout)
        if args.output:
            with open(args.output, "w") as f:
                f.write(r.stdout)
            ok(f"Saved to {args.output}")
        return

    # List all streams
    rows = tshark_run(args.pcap,
                       ["tcp.stream", "ip.src", "tcp.srcport",
                        "ip.dst", "tcp.dstport", "tcp.len"],
                       display_filter="tcp")

    streams = {}
    for row in rows:
        if len(row) < 6:
            continue
        sid, src, sport, dst, dport, length = (row + [""] * 6)[:6]
        if not sid.isdigit():
            continue
        sid = int(sid)
        length = int(length) if length.isdigit() else 0
        if sid not in streams:
            streams[sid] = {"src": src, "sport": sport,
                             "dst": dst, "dport": dport, "bytes": 0, "pkts": 0}
        streams[sid]["bytes"] += length
        streams[sid]["pkts"]  += 1

    print(f"  {'STREAM':<8} {'SRC':<22} {'DST':<22} {'PKTS':>6} {'BYTES':>10}  SVC")
    print("  " + "─" * 80)
    for sid in sorted(streams)[:50]:
        s = streams[sid]
        dport_int = int(s["dport"]) if s["dport"].isdigit() else 0
        svc = _port_svc(dport_int)
        print(f"  {sid:<8} {s['src']+':'+s['sport']:<22} {s['dst']+':'+s['dport']:<22} "
              f"{s['pkts']:>6} {s['bytes']:>10}  {svc}")

    print(f"\n  Total unique streams: {len(streams)}")
    print(f"\n  To dump a specific stream:")
    print(f"  python3 pcap_analyzer.py streams {args.pcap} --stream-id <N>")


# ---------------------------------------------------------------------------
# BEACONING DETECTION
# ---------------------------------------------------------------------------

def cmd_beacon(args):
    require_scapy()
    hdr("C2 BEACONING DETECTION")

    # Group connection timestamps by (src_ip, dst_ip, dst_port)
    connections = collections.defaultdict(list)

    for pkt in stream_pcap(args.pcap):
        if not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
            continue
        src, dst = extract_ips(pkt)
        if not src or not dst:
            continue
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport

        # SYN packets only for TCP (new connections), all for UDP
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if not (flags & 0x02):  # SYN flag
                continue

        key = (src, dst, dport)
        connections[key].append(float(pkt.time))

    beacons = []
    for (src, dst, dport), timestamps in connections.items():
        if len(timestamps) < args.min_count:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if len(intervals) < 2:
            continue
        mean_interval = statistics.mean(intervals)
        jitter = statistics.stdev(intervals) if len(intervals) > 1 else 0
        jitter_pct = (jitter / mean_interval * 100) if mean_interval > 0 else 100

        if jitter_pct <= args.max_jitter:
            beacons.append({
                "src": src, "dst": dst, "dport": dport,
                "count": len(timestamps),
                "mean_interval_s": round(mean_interval, 2),
                "jitter_pct": round(jitter_pct, 1),
                "first": datetime.fromtimestamp(timestamps[0]).strftime("%H:%M:%S"),
                "last":  datetime.fromtimestamp(timestamps[-1]).strftime("%H:%M:%S"),
            })

    beacons.sort(key=lambda x: x["jitter_pct"])

    if not beacons:
        warn(f"No beaconing detected (min_count={args.min_count}, max_jitter={args.max_jitter}%)")
        info("Try: --min-count 3 --max-jitter 20")
        return

    ok(f"{len(beacons)} potential beacon(s) found:\n")
    for b in beacons:
        svc = _port_svc(b["dport"])
        print(f"  {b['src']} → {b['dst']}:{b['dport']} [{svc}]")
        print(f"    count={b['count']}  interval={b['mean_interval_s']}s  "
              f"jitter={b['jitter_pct']}%  {b['first']} → {b['last']}")
        if b["jitter_pct"] < 2:
            print(f"    ⚠️  Near-perfect regularity — very likely automated/C2")
        print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(beacons, f, indent=2)
        ok(f"Saved to {args.output}")


# ---------------------------------------------------------------------------
# IOC EXTRACTION
# ---------------------------------------------------------------------------

IP_RE     = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                        rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|ru|cn|de|uk|info|biz"
                        rb"|gov|edu|xyz|top|club|online|site|tech|co){1}\b", re.IGNORECASE)
URL_RE    = re.compile(rb"https?://[^\s\"'<>\)\]]{4,200}", re.IGNORECASE)
HASH_MD5  = re.compile(rb"\b[a-fA-F0-9]{32}\b")
HASH_SHA1 = re.compile(rb"\b[a-fA-F0-9]{40}\b")
HASH_SHA256 = re.compile(rb"\b[a-fA-F0-9]{64}\b")


def cmd_ioc(args):
    require_scapy()
    hdr("IOC EXTRACTION FROM PACKETS")

    ip_counter     = collections.Counter()
    domain_counter = collections.Counter()
    url_counter    = collections.Counter()
    md5_set, sha1_set, sha256_set = set(), set(), set()

    for pkt in stream_pcap(args.pcap):
        payload = get_payload(pkt)
        if not payload:
            continue

        for m in IP_RE.finditer(payload):
            ip = m.group(0).decode("ascii", errors="ignore")
            if not is_private(ip):
                ip_counter[ip] += 1

        for m in DOMAIN_RE.finditer(payload):
            domain_counter[m.group(0).decode("ascii", errors="ignore").lower()] += 1

        for m in URL_RE.finditer(payload):
            url_counter[m.group(0).decode("ascii", errors="ignore")] += 1

        for m in HASH_MD5.finditer(payload):
            md5_set.add(m.group(0).decode())
        for m in HASH_SHA1.finditer(payload):
            sha1_set.add(m.group(0).decode())
        for m in HASH_SHA256.finditer(payload):
            sha256_set.add(m.group(0).decode())

    out = []

    def section(title, items):
        print(f"\n── {title} ──")
        for val, cnt in (items.most_common(30) if hasattr(items, "most_common") else [(v, 1) for v in items]):
            line = f"  {val}   (x{cnt})"
            print(line)
            out.append(line)

    section(f"External IPs ({len(ip_counter)})", ip_counter)
    section(f"Domains ({len(domain_counter)})", domain_counter)
    section(f"URLs ({len(url_counter)})", url_counter)
    if md5_set:
        print(f"\n── MD5 hashes ({len(md5_set)}) ──")
        for h in md5_set:
            print(f"  {h}")
    if sha1_set:
        print(f"\n── SHA1 hashes ({len(sha1_set)}) ──")
        for h in sha1_set:
            print(f"  {h}")
    if sha256_set:
        print(f"\n── SHA256 hashes ({len(sha256_set)}) ──")
        for h in sha256_set:
            print(f"  {h}")

    if args.output:
        with open(args.output, "w") as f:
            for line in out:
                f.write(line.strip() + "\n")
        ok(f"Saved to {args.output}")


# ---------------------------------------------------------------------------
# FILE CARVING
# ---------------------------------------------------------------------------

def cmd_files(args):
    hdr("HTTP FILE CARVING")

    if not _tshark_available():
        fail("tshark required for file carving")
        sys.exit(1)

    out_dir = args.out_dir or "./carved_files"
    os.makedirs(out_dir, exist_ok=True)
    info(f"Carving HTTP objects to: {out_dir}")

    try:
        r = subprocess.run(
            ["tshark", "-r", args.pcap, "--export-objects",
             f"http,{out_dir}"],
            capture_output=True, text=True, timeout=60
        )
        files = os.listdir(out_dir)
        if files:
            ok(f"Carved {len(files)} file(s):")
            for name in sorted(files):
                size = os.path.getsize(os.path.join(out_dir, name))
                print(f"  {name}  ({size:,} bytes)")
            print(f"\n[~] Run flag hunter on carved files:")
            print(f"  python3 ../flag_hunnter/flag_hunter.py {out_dir}")
            print(f"  python3 ../encoding_decoder/encoding_decoder.py scan {out_dir}")
        else:
            warn("No HTTP objects carved. Capture may be encrypted or not HTTP.")
    except subprocess.TimeoutExpired:
        fail("tshark timed out during carving")


# ---------------------------------------------------------------------------
# EXPORT / FILTER
# ---------------------------------------------------------------------------

def cmd_export(args):
    require_scapy()
    hdr("PCAP EXPORT WITH FILTER")

    if not args.bpf:
        fail("Specify a BPF filter with --bpf, e.g. --bpf 'host 1.2.3.4'")
        sys.exit(1)

    if _tshark_available():
        out = args.output or "filtered.pcap"
        cmd = ["tshark", "-r", args.pcap, "-Y", args.bpf, "-w", out]
        r = subprocess.run(cmd, capture_output=True, timeout=60)
        if r.returncode == 0:
            size = os.path.getsize(out)
            ok(f"Written to {out}  ({size:,} bytes)")
        else:
            fail(f"tshark error: {r.stderr.decode()}")
    else:
        fail("tshark required for pcap export. Install: apt install tshark")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PCAP/pcapng network traffic analyzer for CTF")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_pcap(p):
        p.add_argument("pcap", help="Path to .pcap or .pcapng file")
        p.add_argument("-o", "--output", help="Save results to file")
        return p

    add_pcap(sub.add_parser("summary",  help="Protocol/IP/port overview"))
    add_pcap(sub.add_parser("creds",    help="Extract cleartext credentials"))

    p_dns = add_pcap(sub.add_parser("dns", help="DNS query/response analysis"))
    p_dns.add_argument("--filter-type", help="Filter by record type, e.g. A, AAAA, TXT")

    p_http = add_pcap(sub.add_parser("http", help="HTTP request/response analysis"))
    p_http.add_argument("--flag-pattern", default=FLAG_PATTERN_DEFAULT,
                         help="Regex flag pattern to hunt in HTTP streams")

    p_streams = add_pcap(sub.add_parser("streams", help="List or follow TCP streams"))
    p_streams.add_argument("--stream-id", type=int, help="Dump this specific stream as ASCII")

    p_beacon = add_pcap(sub.add_parser("beacon", help="Detect C2 beaconing (periodic callbacks)"))
    p_beacon.add_argument("--min-count", type=int, default=5,
                           help="Min connection count to consider (default 5)")
    p_beacon.add_argument("--max-jitter", type=float, default=10.0,
                           help="Max jitter %% to flag as beacon (default 10)")

    add_pcap(sub.add_parser("ioc", help="Extract IPs, domains, URLs, hashes from payloads"))

    p_files = add_pcap(sub.add_parser("files", help="Carve transferred files from HTTP"))
    p_files.add_argument("--out-dir", default="./carved_files")

    p_export = add_pcap(sub.add_parser("export", help="Export filtered packets to new pcap"))
    p_export.add_argument("--bpf", help="Wireshark display filter, e.g. 'host 1.2.3.4'")

    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        fail(f"File not found: {args.pcap}")
        sys.exit(1)

    dispatch = {
        "summary": cmd_summary, "creds": cmd_creds, "dns": cmd_dns,
        "http": cmd_http, "streams": cmd_streams, "beacon": cmd_beacon,
        "ioc": cmd_ioc, "files": cmd_files, "export": cmd_export,
    }
    try:
        dispatch[args.cmd](args)
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(0)


if __name__ == "__main__":
    main()
