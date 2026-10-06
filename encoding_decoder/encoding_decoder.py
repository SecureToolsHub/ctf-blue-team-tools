#!/usr/bin/env python3
"""
encoding_decoder.py — Multi-encoding brute-force decoder for CTF forensics.

Inspired by the MedLeak writeup where a flag was hidden in a 150 MB file
using UTF-32LE encoding, buried among high-entropy "garbage" bytes.

Tries every encoding / transform combination against a file or stdin,
prints any match against the flag pattern (or any printable text).

Supported transforms:
  - UTF-8, UTF-16LE, UTF-16BE, UTF-32LE, UTF-32BE
  - Base64, Base64 URL-safe
  - Hex (ascii), ROT13
  - XOR (1-255), Caesar cipher
  - Reverse bytes / reverse text
  - zlib decompress
  - URL decode

Usage:
    # Scan an entire file for flag-shaped strings in all encodings
    python3 encoding_decoder.py scan suspicious.bin

    # Use a custom flag prefix pattern
    python3 encoding_decoder.py scan suspicious.sql --pattern 'flag\\{[^}]+\\}'

    # Decode a single string interactively
    python3 encoding_decoder.py decode "SGVsbG8gV29ybGQ="

    # Extract UTF-32LE text from a file (exact mode from the MedLeak writeup)
    python3 encoding_decoder.py extract-utf32 crm_tizim_baza.sql

    # Try all XOR keys against a hex blob
    python3 encoding_decoder.py xor-scan deadbeef01020304... --pattern 'ctf'

    # Brute-force Caesar on a string
    python3 encoding_decoder.py caesar "Fws{urnmb}"
"""

import argparse
import base64
import codecs
import io
import math
import os
import re
import sys
import zlib
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_PATTERN = r"(?:ctf|flag|CTF|FLAG|HTB|KZN|CKT)\{[^\}]{1,200}\}"
CHUNK = 4 * 1024 * 1024  # 4 MB per read chunk
OVERLAP = 512             # byte overlap to catch cross-chunk patterns


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_decode(data: bytes, encoding: str, errors: str = "ignore") -> str:
    try:
        return data.decode(encoding, errors=errors)
    except Exception:
        return ""


def printable_ratio(s: str, min_len: int = 4) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
    return printable / len(s)


def find_matches(text: str, pattern: re.Pattern) -> list:
    return list(dict.fromkeys(pattern.findall(text)))  # dedup, preserve order


def shannon_entropy(data: bytes) -> float:
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    l = len(data)
    return -sum((c / l) * math.log2(c / l) for c in counts.values())


# ---------------------------------------------------------------------------
# Transforms
# ---------------------------------------------------------------------------

def try_base64(data: bytes) -> bytes | None:
    try:
        return base64.b64decode(data, validate=False)
    except Exception:
        return None


def try_base64_url(data: bytes) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(data + b"==")
    except Exception:
        return None


def try_hex(data: bytes) -> bytes | None:
    try:
        text = data.decode("ascii", errors="ignore").strip()
        clean = re.sub(r"\s", "", text)
        return bytes.fromhex(clean)
    except Exception:
        return None


def try_zlib(data: bytes) -> bytes | None:
    for wbits in [15, -15, 47]:  # zlib, raw deflate, gzip
        try:
            return zlib.decompress(data, wbits)
        except Exception:
            pass
    return None


def xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def url_decode(data: bytes) -> str:
    try:
        return unquote(data.decode("utf-8", errors="ignore"))
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Core scan engine
# ---------------------------------------------------------------------------

ENCODINGS = [
    "utf-8", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be",
    "latin-1", "cp1252",
]

TRANSFORM_CHAINS = [
    ("raw",        lambda d: d),
    ("base64",     lambda d: try_base64(d) or b""),
    ("base64url",  lambda d: try_base64_url(d) or b""),
    ("hex",        lambda d: try_hex(d) or b""),
    ("zlib",       lambda d: try_zlib(d) or b""),
    ("reversed",   lambda d: d[::-1]),
]


def scan_chunk(chunk: bytes, pattern: re.Pattern, verbose: bool = False) -> list:
    """Run all encoding × transform combinations on a bytes chunk."""
    findings = []
    seen = set()

    def record(transform, encoding, match):
        key = match
        if key not in seen:
            seen.add(key)
            findings.append((transform, encoding, match))
            if verbose:
                print(f"    [{transform} / {encoding}] {match}", file=sys.stderr)

    for t_name, t_fn in TRANSFORM_CHAINS:
        transformed = t_fn(chunk)
        if not transformed:
            continue
        for enc in ENCODINGS:
            text = safe_decode(transformed, enc)
            if not text:
                continue
            for m in find_matches(text, pattern):
                record(t_name, enc, m)
            # Also try rot13 on decoded text
            rotated = rot13(text)
            for m in find_matches(rotated, pattern):
                record(f"{t_name}+rot13", enc, m)

    # URL decode raw
    url_text = url_decode(chunk)
    for m in find_matches(url_text, pattern):
        record("url_decode", "utf-8", m)

    # XOR single-byte — only when chunk is small enough
    if len(chunk) <= 64 * 1024:
        for key in range(1, 256):
            xored = xor_bytes(chunk, key)
            for enc in ("utf-8", "latin-1"):
                text = safe_decode(xored, enc)
                for m in find_matches(text, pattern):
                    record(f"xor_{key:#04x}", enc, m)

    return findings


def scan_file(path: str, pattern: re.Pattern, verbose: bool) -> list:
    """Stream through file in overlapping chunks, try all transforms."""
    size = os.path.getsize(path)
    all_findings = []
    prev_tail = b""
    processed = 0

    with open(path, "rb") as f:
        while True:
            raw = f.read(CHUNK)
            if not raw:
                break
            chunk = prev_tail + raw
            findings = scan_chunk(chunk, pattern, verbose)
            all_findings.extend(findings)
            prev_tail = chunk[-OVERLAP:]
            processed += len(raw)
            pct = processed * 100 // size
            print(f"\r  Progress: {pct:3d}%  ({processed:,}/{size:,} bytes)  "
                  f"findings so far: {len(all_findings)}",
                  end="", file=sys.stderr)

    print(file=sys.stderr)
    return all_findings


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_scan(args):
    pattern = re.compile(args.pattern, re.IGNORECASE)
    print(f"[+] File    : {args.file}")
    print(f"[+] Pattern : {args.pattern}")
    print(f"[+] Scanning...\n")

    if not os.path.isfile(args.file):
        print(f"[-] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    findings = scan_file(args.file, pattern, args.verbose)

    print(f"\n[+] Total unique findings: {len(findings)}\n")
    print("=" * 60)
    for i, (transform, encoding, match) in enumerate(findings, 1):
        print(f"  [{i}] {match}")
        print(f"       Transform: {transform}  Encoding: {encoding}")
    print("=" * 60)

    if args.output:
        with open(args.output, "w") as f:
            for transform, encoding, match in findings:
                f.write(f"{transform}\t{encoding}\t{match}\n")
        print(f"\n[+] Saved to {args.output}")


def cmd_decode(args):
    data = args.data.encode() if isinstance(args.data, str) else args.data
    pattern = re.compile(args.pattern, re.IGNORECASE)

    print(f"[+] Input ({len(data)} bytes): {args.data[:80]}")
    print("[+] Trying all transforms...\n")

    findings = scan_chunk(data, pattern, verbose=True)

    if not findings:
        # If no flag pattern matched, print all readable decodings
        print("\n[!] No pattern match. Showing all readable decoded forms:\n")
        for t_name, t_fn in TRANSFORM_CHAINS:
            transformed = t_fn(data)
            if not transformed:
                continue
            for enc in ENCODINGS:
                text = safe_decode(transformed, enc)
                if text and printable_ratio(text) > 0.7:
                    preview = repr(text[:120])
                    print(f"  [{t_name} / {enc}] {preview}")
    else:
        print(f"\n[+] Matched {len(findings)} pattern(s):")
        for transform, encoding, match in findings:
            print(f"  [{transform} / {encoding}] {match}")


def cmd_extract_utf32(args):
    """Directly replicate the MedLeak technique: read file as UTF-32LE, grep for pattern."""
    pattern = re.compile(args.pattern, re.IGNORECASE)
    path = args.file

    if not os.path.isfile(path):
        print(f"[-] File not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Extracting UTF-32LE strings from: {path}")
    print(f"[+] Pattern: {args.pattern}\n")

    found = []
    try:
        with open(path, "r", encoding="utf-32-le", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for m in pattern.findall(line):
                    print(f"  [Line {line_num}] {m}")
                    found.append(m)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

    if not found:
        print("  [!] No matches found with UTF-32LE. Try encoding_decoder.py scan instead.")
    else:
        print(f"\n[+] Total: {len(found)} match(es)")


def cmd_xor_scan(args):
    """Brute-force all single-byte XOR keys against hex or raw input."""
    try:
        data = bytes.fromhex(args.data.replace(" ", "").replace(":", ""))
    except ValueError:
        data = args.data.encode()

    pattern_str = args.pattern
    print(f"[+] XOR brute-force on {len(data)} bytes, looking for: {pattern_str!r}\n")

    for key in range(256):
        xored = xor_bytes(data, key)
        for enc in ("utf-8", "latin-1", "utf-16-le"):
            try:
                text = xored.decode(enc, errors="ignore")
            except Exception:
                continue
            if pattern_str.lower() in text.lower():
                print(f"  [!] XOR key=0x{key:02X} ({key}) / {enc}: {repr(text[:120])}")


def cmd_caesar(args):
    """Brute-force all 25 Caesar shifts on a string."""
    s = args.text
    pattern = re.compile(args.pattern, re.IGNORECASE) if args.pattern else None

    print(f"[+] Caesar brute-force on: {s!r}\n")
    for shift in range(1, 26):
        result = []
        for c in s:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                result.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                result.append(c)
        decoded = "".join(result)
        marker = " ← MATCH" if pattern and pattern.search(decoded) else ""
        print(f"  Shift {shift:2d}: {decoded}{marker}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Multi-encoding brute-force decoder for CTF forensics"
    )
    parser.add_argument("--pattern", default=DEFAULT_PATTERN,
                         help="Regex flag pattern to search for")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Scan a file with all encoding/transform combos")
    p_scan.add_argument("file")
    p_scan.add_argument("--pattern", default=DEFAULT_PATTERN)
    p_scan.add_argument("--output", "-o", help="Save findings to TSV file")
    p_scan.add_argument("--verbose", "-v", action="store_true")

    p_dec = sub.add_parser("decode", help="Try all decodings on a single string/bytes")
    p_dec.add_argument("data", help="String or hex blob to decode")
    p_dec.add_argument("--pattern", default=DEFAULT_PATTERN)

    p_utf32 = sub.add_parser("extract-utf32",
                               help="Extract UTF-32LE strings (MedLeak technique)")
    p_utf32.add_argument("file")
    p_utf32.add_argument("--pattern", default=DEFAULT_PATTERN)

    p_xor = sub.add_parser("xor-scan",
                             help="Brute-force single-byte XOR keys")
    p_xor.add_argument("data", help="Hex string or raw text")
    p_xor.add_argument("--pattern", default="ctf")

    p_caesar = sub.add_parser("caesar", help="Brute-force Caesar cipher (all 25 shifts)")
    p_caesar.add_argument("text")
    p_caesar.add_argument("--pattern", default=None,
                           help="Highlight shifts matching this regex")

    args = parser.parse_args()
    dispatch = {
        "scan": cmd_scan,
        "decode": cmd_decode,
        "extract-utf32": cmd_extract_utf32,
        "xor-scan": cmd_xor_scan,
        "caesar": cmd_caesar,
    }
    try:
        dispatch[args.cmd](args)
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(0)


if __name__ == "__main__":
    main()
