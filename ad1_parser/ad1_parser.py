#!/usr/bin/env python3
"""
ad1_parser.py — AccessData FTK AD1 (Logical Image) forensic parser.

Directly implements the parsing technique from the MedLeak CTF writeup:
fast streaming parser for .ad1 files that can enumerate entries, extract
specific files, and search for artifacts without loading the whole image.

AD1 Format (high-level):
  - 512-byte file header (ADLOGICALIMAGE signature)
  - 128-byte segment header
  - Repeating entry blocks, each containing:
      [40 bytes] ng, nig, nb, sod, dsz  (5 x int64 LE)
      [ 8 bytes] itype, flen             (2 x uint32 LE)
      [flen bytes] filename (UTF-8)
      [if dsz > 0]:
          [8 bytes] chunk_count (int64 LE)
          [(cc+1)*8 bytes] chunk offsets

Usage:
    python3 ad1_parser.py list evidence.ad1
    python3 ad1_parser.py list evidence.ad1 --filter ".bash_history"
    python3 ad1_parser.py extract evidence.ad1 --entry "mrrobot/.bash_history" --out ./extracted/
    python3 ad1_parser.py extract evidence.ad1 --entry "MED-leaks.zip" --out ./extracted/
    python3 ad1_parser.py search evidence.ad1 --keyword "MED-leaks" --keyword ".zip" --keyword "scp"
    python3 ad1_parser.py wsl evidence.ad1   # Find WSL rootfs artifacts
"""

import argparse
import io
import os
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AD1_SIGNATURE = b"ADLOGICALIMAGE"
HEADER_SKIP = 512 + 128  # Logical Image initial offset (from writeup)

ARTIFACT_PATTERNS = [
    ".bash_history", ".zsh_history", ".sh_history",
    "id_rsa", "id_ed25519", ".ssh/authorized_keys",
    "shadow", "passwd",
    "known_hosts", ".netrc",
    ".bashrc", ".profile",
    "rootfs",  # WSL
    ".zip", ".7z", ".rar",
    "wallet.dat",
    "*.sql", "*.db", "*.sqlite",
    "*.pem", "*.pfx", "*.p12",
]

WSL_PATHS = [
    "Packages/CanonicalGroupLimited",
    "Packages/Ubuntu",
    "LocalState/rootfs",
    "AppData/Local/Packages",
]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class AD1Entry:
    __slots__ = ["filename", "offset", "data_size", "chunk_offsets", "itype"]

    def __init__(self, filename, offset, data_size, chunk_offsets, itype):
        self.filename = filename
        self.offset = offset
        self.data_size = data_size
        self.chunk_offsets = chunk_offsets
        self.itype = itype


def _read_exact(f, n: int) -> bytes:
    """Read exactly n bytes or return b'' on EOF."""
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def parse_ad1(ad1_path: str, callback, max_entries: int = 0):
    """
    Stream-parse an AD1 file, calling callback(entry: AD1Entry) for each file entry.
    Skips non-file entries quickly using chunk offset arithmetic.
    """
    file_size = os.path.getsize(ad1_path)

    with open(ad1_path, "rb") as f:
        # Verify signature
        sig = f.read(len(AD1_SIGNATURE))
        if sig != AD1_SIGNATURE:
            raise ValueError(f"Not an AD1 file (signature mismatch: {sig!r})")

        f.seek(HEADER_SKIP)
        count = 0

        while f.tell() < file_size - 512:
            pos = f.tell()
            raw = _read_exact(f, 40)
            if len(raw) < 40:
                break

            try:
                ng, nig, nb, sod, dsz = struct.unpack("<5q", raw)
                itype, flen = struct.unpack("<2I", _read_exact(f, 8))
            except struct.error:
                break

            if flen == 0 or flen > 32768:
                break  # Sanity guard

            fname_bytes = _read_exact(f, flen)
            try:
                fname = fname_bytes.decode("utf-8", errors="replace")
            except Exception:
                fname = repr(fname_bytes)

            chunk_offsets = []
            if dsz > 0:
                cc_raw = _read_exact(f, 8)
                if len(cc_raw) < 8:
                    break
                cc, = struct.unpack("<q", cc_raw)
                if cc < 0 or cc > 100_000:
                    break  # Sanity guard
                off_raw = _read_exact(f, 8 * (cc + 1))
                if len(off_raw) < 8 * (cc + 1):
                    break
                chunk_offsets = list(struct.unpack(f"<{cc+1}q", off_raw))
                # Skip data bytes (they're elsewhere in the file at chunk_offsets)
                # The writeup skips: carr[-1] - carr[0] bytes
                skip_n = chunk_offsets[-1] - chunk_offsets[0]
                if 0 < skip_n < file_size:
                    f.seek(skip_n, os.SEEK_CUR)

            entry = AD1Entry(
                filename=fname,
                offset=pos,
                data_size=dsz,
                chunk_offsets=chunk_offsets,
                itype=itype,
            )
            callback(entry)
            count += 1
            if max_entries and count >= max_entries:
                break


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_list(args):
    entries = []
    pattern = args.filter.lower() if args.filter else None

    def collect(entry):
        if pattern and pattern not in entry.filename.lower():
            return
        entries.append(entry)

    print(f"[+] Parsing: {args.ad1}")
    try:
        parse_ad1(args.ad1, collect)
    except Exception as e:
        print(f"[-] Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Found {len(entries)} entries" +
          (f" matching '{args.filter}'" if pattern else "") + "\n")
    print(f"  {'FILENAME':<70} {'SIZE':>12}  ITYPE")
    print("  " + "-" * 90)
    for e in entries:
        size_str = f"{e.data_size:,}" if e.data_size else "-"
        print(f"  {e.filename[:70]:<70} {size_str:>12}  {e.itype}")


def cmd_wsl(args):
    """Find WSL-related artifacts (rootfs, bash_history, etc.)."""
    print(f"[+] Hunting for WSL artifacts in: {args.ad1}")
    wsl_hits = []

    def collect(entry):
        fname_lower = entry.filename.lower()
        for pat in WSL_PATHS:
            if pat.lower() in fname_lower:
                wsl_hits.append(entry)
                return
        # Also pick up bash_history inside any wsl-looking path
        if "rootfs" in fname_lower or "wsl" in fname_lower:
            wsl_hits.append(entry)

    try:
        parse_ad1(args.ad1, collect)
    except Exception as e:
        print(f"[-] Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] {len(wsl_hits)} WSL-related entries found:\n")
    for e in wsl_hits:
        size_str = f"{e.data_size:,} bytes" if e.data_size else "-"
        print(f"  {e.filename}  ({size_str})")

    print("\n[~] Interesting entries to extract:")
    high_value = [".bash_history", ".zsh_history", "shadow", "id_rsa", ".zip", ".sql"]
    for e in wsl_hits:
        if any(kw in e.filename.lower() for kw in high_value):
            print(f"  python3 ad1_parser.py extract {args.ad1} --entry \"{e.filename}\" --out ./extracted/")


def cmd_search(args):
    """Search all entry filenames for keywords."""
    keywords = [k.lower() for k in args.keyword]
    hits = []

    def collect(entry):
        fname_lower = entry.filename.lower()
        if any(kw in fname_lower for kw in keywords):
            hits.append(entry)

    print(f"[+] Searching entries for: {args.keyword}")
    try:
        parse_ad1(args.ad1, collect)
    except Exception as e:
        print(f"[-] Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] {len(hits)} matches:\n")
    for e in hits:
        size_str = f"{e.data_size:,}" if e.data_size else "-"
        print(f"  [{size_str:>12} bytes]  {e.filename}")
        print(f"    Extract: python3 ad1_parser.py extract {args.ad1} "
              f"--entry \"{e.filename}\" --out ./extracted/")


def cmd_extract(args):
    """
    Extract a specific file from an AD1 image.

    NOTE: Full reconstruction requires reading at the chunk offsets from within
    the image. This implementation provides the entry metadata and offset info
    needed to do a raw copy. For complete reconstruction, use FTK Imager or
    implement chunk-based reading per the offset table.
    """
    target = args.entry.lower()
    matched = []

    def collect(entry):
        if target in entry.filename.lower():
            matched.append(entry)

    print(f"[+] Searching for entry: {args.entry}")
    try:
        parse_ad1(args.ad1, collect)
    except Exception as e:
        print(f"[-] Parse error: {e}", file=sys.stderr)
        sys.exit(1)

    if not matched:
        print(f"[-] No entries found matching '{args.entry}'")
        sys.exit(1)

    print(f"[+] Found {len(matched)} matching entries:")
    for e in matched:
        print(f"  {e.filename}  ({e.data_size:,} bytes if dsz)")
        print(f"  Chunk offsets: {e.chunk_offsets[:5]}" +
              (" ..." if len(e.chunk_offsets) > 5 else ""))

    print(f"\n[~] To extract with FTK Imager CLI:")
    print(f"  ftkimager {args.ad1} --e01 --nopassword")
    print(f"\n[~] Alternatively, use Autopsy or mount with:")
    print(f"  ewfmount {args.ad1} /mnt/evidence/")
    print(f"  ls /mnt/evidence/")
    print(f"\n[~] Python chunk-based extraction (if offsets are valid):")
    e = matched[0]
    if e.chunk_offsets and len(e.chunk_offsets) >= 2:
        out_dir = args.out or "./extracted"
        out_name = Path(e.filename).name
        print(f"""
import os
ad1_path = "{args.ad1}"
out_path = "{out_dir}/{out_name}"
chunk_offsets = {e.chunk_offsets}

os.makedirs("{out_dir}", exist_ok=True)
with open(ad1_path, "rb") as f_in, open(out_path, "wb") as f_out:
    for i in range(len(chunk_offsets) - 1):
        start = chunk_offsets[i]
        end = chunk_offsets[i + 1]
        size = end - start
        f_in.seek(start)
        f_out.write(f_in.read(size))
print(f"Extracted to: {{out_path}}")
""")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AccessData FTK AD1 forensic image parser"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="List all entries in the image")
    p_list.add_argument("ad1", help="Path to .ad1 file")
    p_list.add_argument("--filter", help="Show only entries containing this string")

    p_wsl = sub.add_parser("wsl", help="Find WSL rootfs artifacts")
    p_wsl.add_argument("ad1")

    p_search = sub.add_parser("search", help="Search entry filenames for keywords")
    p_search.add_argument("ad1")
    p_search.add_argument("--keyword", action="append", required=True,
                           help="Keyword to search for (can be repeated)")

    p_extract = sub.add_parser("extract", help="Extract a specific file")
    p_extract.add_argument("ad1")
    p_extract.add_argument("--entry", required=True, help="Filename to find (substring match)")
    p_extract.add_argument("--out", default="./extracted", help="Output directory")

    args = parser.parse_args()
    dispatch = {
        "list": cmd_list,
        "wsl": cmd_wsl,
        "search": cmd_search,
        "extract": cmd_extract,
    }
    try:
        dispatch[args.cmd](args)
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(0)


if __name__ == "__main__":
    main()
