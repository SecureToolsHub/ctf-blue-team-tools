#!/usr/bin/env python3
"""
zipcrypto_helper.py — Analyze ZIP archives for known-plaintext-attack
(Biham-Kocher / bkcrack) viability, and auto-generate plaintext
fragments from known file-format magic bytes.

Background: ZipCrypto (the "traditional" ZIP encryption, flag_bits
0x1) is broken by a known-plaintext attack if you have >= ~12
contiguous bytes of the DECOMPRESSED content of any one entry.
STORE (uncompressed) entries are ideal because the plaintext bytes
line up exactly. AES-encrypted entries (WinZip AES) are NOT
vulnerable to this attack at all.

Subcommands:
  list             Report every entry: encryption, compression,
                    and KPA viability verdict.
  gen-plaintext     Write a magic-byte plaintext fragment for a
                    given entry (auto-detected by extension, or
                    forced with --type), ready for `bkcrack -p`.
  suggest           Do both: report + auto-generate plaintext files
                    for every viable entry, and print ready-to-run
                    bkcrack commands.

Usage:
    python3 zipcrypto_helper.py list archive.zip
    python3 zipcrypto_helper.py suggest archive.zip -o ./bkcrack_work
    python3 zipcrypto_helper.py gen-plaintext archive.zip "photo.png" --type png
"""

import argparse
import os
import sys
import zipfile

# name, extensions, offset, hex bytes, confidence note
MAGIC_DB = [
    {"name": "png",     "ext": [".png"],
     "offset": 0, "hex": "89504e470d0a1a0a0000000d49484452",
     "note": "16 fixed bytes (signature + IHDR chunk header) — HIGH confidence"},

    {"name": "gif",      "ext": [".gif"],
     "offset": 0, "hex": "474946383961",
     "note": "6 bytes 'GIF89a' (try 474946383761 for GIF87a) — MEDIUM"},

    {"name": "pdf",      "ext": [".pdf"],
     "offset": 0, "hex": "255044462d312e",
     "note": "7 bytes '%PDF-1.' (version digit varies) — MEDIUM"},

    {"name": "gzip",     "ext": [".gz", ".tar.gz", ".tgz"],
     "offset": 0, "hex": "1f8b08",
     "note": "3 bytes magic+method — LOW, combine with other known bytes if possible"},

    {"name": "zip",      "ext": [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"],
     "offset": 0, "hex": "504b0304",
     "note": "4 bytes 'PK\\x03\\x04' only — LOW alone. Tip: create a same-tool sample "
             "file locally to recover more known header bytes"},

    {"name": "7z",       "ext": [".7z"],
     "offset": 0, "hex": "377abcaf271c",
     "note": "6 fixed signature bytes — HIGH"},

    {"name": "rar4",     "ext": [".rar"],
     "offset": 0, "hex": "526172211a0700",
     "note": "7 fixed bytes (RAR 4.x signature) — HIGH"},

    {"name": "rar5",     "ext": [".rar"],
     "offset": 0, "hex": "526172211a070100",
     "note": "8 fixed bytes (RAR 5.x signature) — HIGH"},

    {"name": "sqlite",   "ext": [".sqlite", ".db", ".sqlite3"],
     "offset": 0, "hex": "53514c69746520666f726d6174203300",
     "note": "16 fixed bytes 'SQLite format 3\\0' — HIGH confidence"},

    {"name": "elf",      "ext": [".elf", ".bin", ".so", ""],
     "offset": 0, "hex": "7f454c4602010100",
     "note": "8 bytes; assumes 64-bit little-endian — MEDIUM, verify class/endianness"},

    {"name": "class",    "ext": [".class"],
     "offset": 0, "hex": "cafebabe",
     "note": "4 fixed bytes (Java magic), version bytes vary — MEDIUM"},

    {"name": "ico",      "ext": [".ico"],
     "offset": 0, "hex": "00000100",
     "note": "4 bytes — MEDIUM"},

    {"name": "ogg",      "ext": [".ogg"],
     "offset": 0, "hex": "4f676753" + "00",
     "note": "5 bytes 'OggS' + version — MEDIUM"},

    {"name": "flac",     "ext": [".flac"],
     "offset": 0, "hex": "664c6143",
     "note": "4 fixed bytes 'fLaC' — MEDIUM"},

    {"name": "wav",      "ext": [".wav"],
     "offset": 8, "hex": "57415645",
     "note": "4 bytes 'WAVE' AT OFFSET 8 (bytes 4-7 are file size, unknown) "
             "— use bkcrack's -o/--offset flag — MEDIUM-HIGH"},

    {"name": "avi",      "ext": [".avi"],
     "offset": 8, "hex": "41564920",
     "note": "4 bytes 'AVI ' AT OFFSET 8 — use bkcrack's -o flag — MEDIUM-HIGH"},

    {"name": "webp",     "ext": [".webp"],
     "offset": 8, "hex": "57454250",
     "note": "4 bytes 'WEBP' AT OFFSET 8 — use bkcrack's -o flag — MEDIUM-HIGH"},

    {"name": "pcap",     "ext": [".pcap"],
     "offset": 0, "hex": "d4c3b2a1",
     "note": "4 fixed bytes (little-endian pcap magic) — HIGH"},

    {"name": "pcapng",   "ext": [".pcapng"],
     "offset": 0, "hex": "0a0d0d0a",
     "note": "4 fixed bytes (pcapng block magic) — HIGH"},
]

EXT_INDEX = {}
for entry in MAGIC_DB:
    for ext in entry["ext"]:
        EXT_INDEX.setdefault(ext.lower(), []).append(entry)


def parse_extra_fields(extra: bytes):
    """Yield (header_id, data) tuples from a ZipInfo.extra blob."""
    i = 0
    out = []
    while i + 4 <= len(extra):
        header_id = int.from_bytes(extra[i:i + 2], "little")
        size = int.from_bytes(extra[i + 2:i + 4], "little")
        data = extra[i + 4:i + 4 + size]
        out.append((header_id, data))
        i += 4 + size
    return out


AES_EXTRA_ID = 0x9901


def analyze_entry(info: zipfile.ZipInfo):
    encrypted = bool(info.flag_bits & 0x1)
    is_aes = False
    real_compress = info.compress_type

    if info.compress_type == 99:  # AE-x, real method is in the extra field
        is_aes = True
    for header_id, data in parse_extra_fields(info.extra):
        if header_id == AES_EXTRA_ID:
            is_aes = True
            if len(data) >= 4:
                real_compress = int.from_bytes(data[2:4], "little")

    if not encrypted:
        verdict = "NOT ENCRYPTED"
    elif is_aes:
        verdict = "AES ENCRYPTED — bkcrack KPA does NOT apply (needs password attack instead)"
    elif real_compress == zipfile.ZIP_STORED:
        verdict = "VIABLE — ZipCrypto + STORE (ideal for known-plaintext attack)"
    elif real_compress == zipfile.ZIP_DEFLATED:
        verdict = "POSSIBLE — ZipCrypto + DEFLATE (KPA works but needs more known bytes)"
    else:
        verdict = f"ZipCrypto + compress_type={real_compress} (support varies)"

    return {
        "filename": info.filename,
        "encrypted": encrypted,
        "is_aes": is_aes,
        "compress_type": real_compress,
        "flag_bits": info.flag_bits,
        "file_size": info.file_size,
        "compress_size": info.compress_size,
        "verdict": verdict,
    }


def cmd_list(args):
    with zipfile.ZipFile(args.zipfile) as zf:
        print(f"{'FILENAME':<40} {'FLAGS':<8} {'METHOD':<8} {'SIZE':>10}  VERDICT")
        print("-" * 110)
        for info in zf.infolist():
            r = analyze_entry(info)
            print(f"{r['filename'][:40]:<40} {hex(r['flag_bits']):<8} "
                  f"{r['compress_type']:<8} {r['file_size']:>10}  {r['verdict']}")


def find_magic(filename, forced_type=None):
    if forced_type:
        for entry in MAGIC_DB:
            if entry["name"] == forced_type:
                return entry
        return None
    ext = os.path.splitext(filename)[1].lower()
    candidates = EXT_INDEX.get(ext)
    return candidates[0] if candidates else None


def write_plaintext(entry, out_path):
    data = bytes.fromhex(entry["hex"])
    with open(out_path, "wb") as f:
        f.write(data)
    return len(data)


def cmd_gen_plaintext(args):
    entry = find_magic(args.entry, args.type)
    if not entry:
        print(f"No magic-byte signature known for '{args.entry}'"
              f"{' (type: ' + args.type + ')' if args.type else ''}.", file=sys.stderr)
        print("Available types: " + ", ".join(sorted({e['name'] for e in MAGIC_DB})),
              file=sys.stderr)
        sys.exit(1)

    out_path = args.out or (os.path.splitext(os.path.basename(args.entry))[0] + "_plaintext.bin")
    n = write_plaintext(entry, out_path)
    print(f"[+] Wrote {n} bytes to {out_path}   ({entry['note']})")

    offset_flag = f" -o {entry['offset']}" if entry["offset"] else ""
    print("\nNext step:")
    print(f"  bkcrack -C {args.zipfile} -c \"{args.entry}\" -p {out_path}{offset_flag}")


def cmd_suggest(args):
    os.makedirs(args.out, exist_ok=True)
    with zipfile.ZipFile(args.zipfile) as zf:
        entries = zf.infolist()

    print(f"{'FILENAME':<40} {'METHOD':<8} VERDICT")
    print("-" * 100)
    any_viable = False
    for info in entries:
        r = analyze_entry(info)
        print(f"{r['filename'][:40]:<40} {r['compress_type']:<8} {r['verdict']}")

        if "VIABLE" in r["verdict"] or "POSSIBLE" in r["verdict"]:
            magic = find_magic(r["filename"])
            if not magic:
                print(f"    (no known magic bytes for this extension — supply your own "
                      f"plaintext with `bkcrack -p`)")
                continue
            any_viable = True
            safe_name = r["filename"].replace("/", "_").replace("\\", "_")
            out_path = os.path.join(args.out, safe_name + ".plaintext.bin")
            n = write_plaintext(magic, out_path)
            offset_flag = f" -o {magic['offset']}" if magic["offset"] else ""
            print(f"    -> generated {n}-byte plaintext: {out_path}   ({magic['note']})")
            print(f"    -> bkcrack -C {args.zipfile} -c \"{r['filename']}\" "
                  f"-p {out_path}{offset_flag}")

    if not any_viable:
        print("\nNo entries with a recognized magic-byte format were found viable. "
              "Use `list` to review verdicts, or supply plaintext manually.")
    else:
        print(f"\nPlaintext fragments written to {args.out}/")
        print("After bkcrack recovers keys from one entry, unlock the whole archive with:")
        print(f"  bkcrack -C {args.zipfile} -k <key0> <key1> <key2> "
              f"-U {os.path.splitext(args.zipfile)[0]}_unlocked.zip unlocked")


def main():
    parser = argparse.ArgumentParser(description="ZipCrypto known-plaintext-attack helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="Report entries and KPA viability")
    p_list.add_argument("zipfile")
    p_list.set_defaults(func=cmd_list)

    p_gen = sub.add_parser("gen-plaintext", help="Write a magic-byte plaintext fragment")
    p_gen.add_argument("zipfile")
    p_gen.add_argument("entry", help="Entry filename inside the zip")
    p_gen.add_argument("--type", help="Force a specific format (see list in error output)")
    p_gen.add_argument("--out", help="Output path for the plaintext fragment")
    p_gen.set_defaults(func=cmd_gen_plaintext)

    p_sug = sub.add_parser("suggest", help="Analyze + auto-generate plaintext for all viable entries")
    p_sug.add_argument("zipfile")
    p_sug.add_argument("-o", "--out", default="./bkcrack_work", help="Output directory")
    p_sug.set_defaults(func=cmd_suggest)

    args = parser.parse_args()
    if not os.path.isfile(args.zipfile):
        print(f"File not found: {args.zipfile}", file=sys.stderr)
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
