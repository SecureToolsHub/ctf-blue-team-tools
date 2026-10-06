#!/usr/bin/env python3
"""
flag_hunter.py — Search files for flag{...}-style patterns across
multiple encodings and light obfuscation layers in one pass.

Handles the cases that manual grep misses:
    - UTF-16LE / UTF-16BE / UTF-32LE / UTF-32BE text embedded in
      otherwise binary/random data (e.g. a flag hidden inside a
      150MB blob of high-entropy garbage bytes)
    - Base64-encoded flags
    - ROT13-obfuscated flags
    - Large files, scanned in chunks with overlap so a flag split
      across a chunk boundary isn't missed

Usage:
    python3 flag_hunter.py ./evidence
    python3 flag_hunter.py crm_tizim_baza.sql
    python3 flag_hunter.py ./evidence --prefixes ctf,flag,HTB
    python3 flag_hunter.py ./evidence --pattern 'HTB\\{[^}]+\\}'
    python3 flag_hunter.py ./evidence --no-base64 --no-rot13
"""

import argparse
import base64
import codecs
import os
import re
import sys

DEFAULT_PREFIXES = ["flag", "ctf", "FLAG", "CTF"]

ENCODINGS = {
    "utf-8": "utf-8",
    "utf-16le": "utf-16-le",
    "utf-16be": "utf-16-be",
    "utf-32le": "utf-32-le",
    "utf-32be": "utf-32-be",
    "latin-1": "latin-1",
}

CHUNK_SIZE = 8 * 1024 * 1024   # 8 MB
OVERLAP = 512                  # bytes of overlap between chunks

BASE64_CANDIDATE_RE = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
PRINTABLE_ASCII_RE = re.compile(rb"[\x20-\x7e]{20,}")


def build_pattern(user_pattern, prefixes):
    if user_pattern:
        return re.compile(user_pattern.encode() if isinstance(user_pattern, str) else user_pattern)
    alt = "|".join(re.escape(p) for p in prefixes)
    # generic fallback also catches custom format prefixes
    pat = rf"(?:{alt}|[A-Za-z0-9_]{{2,20}})\{{[^{{}}\r\n]{{3,200}}\}}"
    return re.compile(pat)


def iter_files(path):
    if os.path.isfile(path):
        yield path
    else:
        for root, _, files in os.walk(path):
            if ".git" in root.split(os.sep):
                continue
            for name in files:
                yield os.path.join(root, name)


def scan_text_encodings(chunk: bytes, pattern: re.Pattern, encodings, seen):
    hits = []
    for label, codec_name in encodings.items():
        try:
            text = chunk.decode(codec_name, errors="ignore")
        except Exception:
            continue
        for m in re.finditer(pattern.pattern.decode() if isinstance(pattern.pattern, bytes) else pattern.pattern, text):
            val = m.group(0)
            key = (label, val)
            if key not in seen:
                seen.add(key)
                hits.append((label, val))
    return hits


def scan_base64(chunk: bytes, pattern: re.Pattern, seen):
    hits = []
    for m in BASE64_CANDIDATE_RE.finditer(chunk):
        candidate = m.group(0)
        for pad_try in (0, 1, 2):
            padded = candidate + b"=" * pad_try
            try:
                decoded = base64.b64decode(padded, validate=False)
            except Exception:
                continue
            try:
                text = decoded.decode("utf-8", errors="ignore")
            except Exception:
                continue
            for match in re.finditer(pattern.pattern.decode() if isinstance(pattern.pattern, bytes) else pattern.pattern, text):
                val = match.group(0)
                key = ("base64", val)
                if key not in seen:
                    seen.add(key)
                    hits.append(("base64", val))
            break
    return hits


def scan_rot13(chunk: bytes, pattern: re.Pattern, seen):
    hits = []
    for m in PRINTABLE_ASCII_RE.finditer(chunk):
        segment = m.group(0).decode("ascii", errors="ignore")
        rotated = codecs.decode(segment, "rot13")
        for match in re.finditer(pattern.pattern.decode() if isinstance(pattern.pattern, bytes) else pattern.pattern, rotated):
            val = match.group(0)
            key = ("rot13", val)
            if key not in seen:
                seen.add(key)
                hits.append(("rot13", val))
    return hits


def scan_file(path, pattern, encodings, use_base64, use_rot13, chunk_size, max_size):
    results = []
    seen = set()
    try:
        size = os.path.getsize(path)
    except OSError:
        return results
    if max_size and size > max_size:
        return results

    try:
        with open(path, "rb") as f:
            prev_tail = b""
            offset = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                window = prev_tail + chunk

                for label, val in scan_text_encodings(window, pattern, encodings, seen):
                    results.append((label, val))
                if use_base64:
                    for label, val in scan_base64(window, pattern, seen):
                        results.append((label, val))
                if use_rot13:
                    for label, val in scan_rot13(window, pattern, seen):
                        results.append((label, val))

                prev_tail = window[-OVERLAP:] if len(window) > OVERLAP else window
                offset += len(chunk)
    except (OSError, PermissionError):
        pass

    return results


def main():
    parser = argparse.ArgumentParser(description="Multi-encoding flag/IOC hunter")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--prefixes", default=",".join(DEFAULT_PREFIXES),
                         help="Comma-separated flag prefixes, e.g. ctf,flag,HTB")
    parser.add_argument("--pattern", default=None,
                         help="Full custom regex, overrides --prefixes")
    parser.add_argument("--encodings", default=",".join(ENCODINGS.keys()),
                         help=f"Comma-separated encodings to try (default: all of {list(ENCODINGS.keys())})")
    parser.add_argument("--no-base64", action="store_true", help="Skip base64 decode layer")
    parser.add_argument("--no-rot13", action="store_true", help="Skip ROT13 decode layer")
    parser.add_argument("--chunk-size", type=int, default=CHUNK_SIZE)
    parser.add_argument("--max-size", type=int, default=0,
                         help="Skip files larger than this many bytes (0 = no limit)")
    parser.add_argument("-o", "--output", help="Write findings to file")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    prefixes = [p.strip() for p in args.prefixes.split(",") if p.strip()]
    pattern = build_pattern(args.pattern, prefixes)

    chosen_encodings = {}
    for name in args.encodings.split(","):
        name = name.strip().lower()
        if name in ENCODINGS:
            chosen_encodings[name] = ENCODINGS[name]

    all_findings = []
    files = list(iter_files(args.path))
    print(f"[+] Scanning {len(files)} file(s) under {args.path}")
    print(f"[+] Pattern: {pattern.pattern}")
    print(f"[+] Encodings: {list(chosen_encodings.keys())}"
          f"{' + base64' if not args.no_base64 else ''}"
          f"{' + rot13' if not args.no_rot13 else ''}\n")

    for idx, f in enumerate(files, 1):
        hits = scan_file(f, pattern, chosen_encodings,
                          not args.no_base64, not args.no_rot13,
                          args.chunk_size, args.max_size)
        if hits:
            print(f"[FOUND] {f}")
            for label, val in hits:
                print(f"    ({label}) {val}")
                all_findings.append((f, label, val))
        if idx % 50 == 0:
            print(f"  ... {idx}/{len(files)} files scanned", file=sys.stderr)

    print(f"\n{'-'*60}")
    print(f"Total unique findings: {len(all_findings)}")

    if args.output:
        with open(args.output, "w") as out:
            for f, label, val in all_findings:
                out.write(f"{f}\t{label}\t{val}\n")
        print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
