#!/usr/bin/env python3
"""
entropy_scan.py — Shannon entropy scanner with ASCII visualization.

Finds encrypted/compressed/random blobs hiding in plain data, or
(just as useful) small plaintext/structured regions hiding inside a
large high-entropy blob — exactly the pattern that revealed the
UTF-32LE flag buried in a 150MB "random garbage" SQL file.

Two modes:
  Overview  — splits the whole file into N rows (coarse, fast, good
              for multi-GB files) and draws an ASCII entropy graph.
  Zoom      — re-scans a specific byte range at fine resolution once
              the overview points you at something interesting.

Usage:
    python3 entropy_scan.py bigfile.bin
    python3 entropy_scan.py bigfile.bin --rows 150
    python3 entropy_scan.py bigfile.bin --start 0x4AF0000 --end 0x4B00000 --block-size 256
    python3 entropy_scan.py bigfile.bin --top 10
    python3 entropy_scan.py bigfile.bin --csv entropy.csv
"""

import argparse
import math
import os
import sys
from collections import Counter

BAR_WIDTH = 50
MAX_ENTROPY = 8.0  # bits per byte, theoretical max


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def classify(entropy: float) -> str:
    if entropy >= 7.5:
        return "HIGH (encrypted/compressed/random)"
    if entropy <= 3.0:
        return "LOW (structured/sparse/repetitive)"
    if 3.0 < entropy < 6.0:
        return "MID (likely text/plaintext)"
    return "MID-HIGH"


def bar(entropy: float, width: int = BAR_WIDTH) -> str:
    filled = int((entropy / MAX_ENTROPY) * width)
    filled = max(0, min(width, filled))
    return "#" * filled + "-" * (width - filled)


def scan_blocks(path, block_size, start=0, end=None):
    """Yield (offset, entropy) for sequential blocks in [start, end)."""
    size = os.path.getsize(path)
    if end is None or end > size:
        end = size
    with open(path, "rb") as f:
        f.seek(start)
        offset = start
        while offset < end:
            to_read = min(block_size, end - offset)
            data = f.read(to_read)
            if not data:
                break
            yield offset, shannon_entropy(data)
            offset += len(data)


def mean_std(values):
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    m = sum(values) / n
    var = sum((v - m) ** 2 for v in values) / n
    return m, math.sqrt(var)


def format_offset(o):
    return f"0x{o:08X}"


def main():
    parser = argparse.ArgumentParser(description="Shannon entropy scanner with ASCII graph")
    parser.add_argument("path", help="File to scan")
    parser.add_argument("--rows", type=int, default=120,
                         help="Number of rows in the overview graph (default 120)")
    parser.add_argument("--block-size", type=int, default=None,
                         help="Override block size in bytes (default: filesize / rows)")
    parser.add_argument("--start", default=None, help="Start offset (decimal or 0x-hex) for zoom mode")
    parser.add_argument("--end", default=None, help="End offset (decimal or 0x-hex) for zoom mode")
    parser.add_argument("--anomaly-k", type=float, default=1.5,
                         help="Std-dev multiplier for anomaly flagging (default 1.5)")
    parser.add_argument("--top", type=int, default=10,
                         help="Show top N most anomalous blocks (default 10)")
    parser.add_argument("--csv", help="Write full per-block entropy data to CSV")
    args = parser.parse_args()

    if not os.path.isfile(args.path):
        print(f"File not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    size = os.path.getsize(args.path)

    def parse_off(v):
        if v is None:
            return None
        v = v.strip()
        return int(v, 16) if v.lower().startswith("0x") else int(v)

    start = parse_off(args.start) or 0
    end = parse_off(args.end) or size

    if args.block_size:
        block_size = args.block_size
    else:
        span = end - start
        block_size = max(1, span // args.rows)

    mode = "ZOOM" if (args.start or args.end) else "OVERVIEW"
    print(f"[+] File: {args.path}  ({size:,} bytes)")
    print(f"[+] Mode: {mode}   range: {format_offset(start)} - {format_offset(end)}")
    print(f"[+] Block size: {block_size:,} bytes\n")

    blocks = list(scan_blocks(args.path, block_size, start, end))
    entropies = [e for _, e in blocks]
    m, sd = mean_std(entropies)

    print(f"{'OFFSET':>12}  {'ENTROPY':>7}  GRAPH" + " " * (BAR_WIDTH - 5) + "CLASS")
    print("-" * (12 + 2 + 7 + 2 + BAR_WIDTH + 2 + 20))

    anomalies = []
    for offset, ent in blocks:
        deviation = abs(ent - m)
        is_anomaly = sd > 0 and deviation > args.anomaly_k * sd
        marker = "  <== ANOMALY" if is_anomaly else ""
        print(f"{format_offset(offset):>12}  {ent:7.4f}  {bar(ent)}  {classify(ent)}{marker}")
        if is_anomaly:
            anomalies.append((offset, ent, deviation))

    print(f"\n{'-'*60}")
    print(f"Mean entropy: {m:.4f}   Std dev: {sd:.4f}")
    print(f"Blocks scanned: {len(blocks)}")

    if anomalies:
        anomalies.sort(key=lambda x: -x[2])
        print(f"\nTop {min(args.top, len(anomalies))} anomalous block(s) "
              f"(deviate > {args.anomaly_k} std dev from mean):")
        for offset, ent, dev in anomalies[:args.top]:
            end_off = offset + block_size
            print(f"  {format_offset(offset)} - {format_offset(end_off)}"
                  f"   entropy={ent:.4f}   deviation={dev:.4f}")
        print("\nNext step: zoom into a region, e.g.")
        off0 = anomalies[0][0]
        print(f"  python3 entropy_scan.py {args.path} "
              f"--start {format_offset(max(0, off0 - block_size))} "
              f"--end {format_offset(off0 + 2*block_size)} --block-size 256")
        print("Or feed the whole file to flag_hunter.py once you've narrowed the range.")
    else:
        print("\nNo strong anomalies at this resolution. "
              "Try --rows with a larger value, or a smaller --block-size, to zoom in.")

    if args.csv:
        with open(args.csv, "w") as f:
            f.write("offset,entropy\n")
            for offset, ent in blocks:
                f.write(f"{offset},{ent:.6f}\n")
        print(f"\n[+] Saved raw data to {args.csv}")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
