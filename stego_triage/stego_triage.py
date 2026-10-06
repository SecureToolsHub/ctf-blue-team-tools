#!/usr/bin/env python3
"""
stego_triage.py — Steganography detection and file metadata triage for CTF.

Covers the most common CTF stego techniques in a single-pass triage:
  1. File signature mismatch (extension vs. magic bytes)
  2. EXIF / metadata extraction (GPS, comments, author, timestamps)
  3. Appended data after EOF (data hidden after image end marker)
  4. LSB (Least Significant Bit) steganography detection & extraction
  5. String extraction from binary/image files
  6. Embedded file detection (wraps binwalk)
  7. Image channel analysis (alpha channel, color histograms)
  8. PNG chunk inspector (custom chunks often hide data)
  9. Base64/hex strings hidden in metadata or comments

Usage:
    python3 stego_triage.py scan    image.png          # Full auto triage
    python3 stego_triage.py scan    image.jpg --all    # Include LSB brute-force
    python3 stego_triage.py exif    image.jpg          # EXIF/metadata dump
    python3 stego_triage.py lsb     image.png          # LSB bit extraction
    python3 stego_triage.py append  image.png          # Check data after EOF
    python3 stego_triage.py chunks  image.png          # PNG chunk inspector
    python3 stego_triage.py strings image.png --min 8  # String extraction
    python3 stego_triage.py magic   suspicious_file    # Magic bytes vs. extension
    python3 stego_triage.py binwalk image.png          # Embedded file detection
"""

import argparse
import binascii
import io
import math
import os
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path

try:
    from PIL import Image, ExifTags
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FLAG_RE = re.compile(
    r"(?:ctf|flag|FLAG|CTF|HTB|THM)\{[^\}]{1,200}\}|"
    r"[A-Za-z0-9+/]{20,}={0,2}",  # base64-like
    re.IGNORECASE
)

# Known file magic bytes: (magic_hex, extension, description)
MAGIC_DB = [
    ("89504e47", ".png",  "PNG image"),
    ("ffd8ff",   ".jpg",  "JPEG image"),
    ("47494638", ".gif",  "GIF image"),
    ("424d",     ".bmp",  "BMP image"),
    ("52494646", ".wav",  "WAV audio / RIFF container"),
    ("49443302", ".mp3",  "MP3 audio (ID3v2.2)"),
    ("49443303", ".mp3",  "MP3 audio (ID3v2.3)"),
    ("504b0304", ".zip",  "ZIP archive"),
    ("504b0506", ".zip",  "ZIP archive (empty)"),
    ("1f8b08",   ".gz",   "Gzip archive"),
    ("377abcaf", ".7z",   "7-Zip archive"),
    ("52617221", ".rar",  "RAR archive"),
    ("25504446", ".pdf",  "PDF document"),
    ("7f454c46", "",      "ELF binary (Linux)"),
    ("4d5a",     ".exe",  "PE / EXE (Windows)"),
    ("cafebabe", ".class","Java class file"),
    ("d4c3b2a1", ".pcap", "PCAP (LE)"),
    ("0a0d0d0a", ".pcapng","PCAPNG"),
    ("4f676753", ".ogg",  "OGG audio"),
    ("664c6143", ".flac", "FLAC audio"),
    ("00000020", ".mp4",  "MP4 video (ftyp)"),
    ("664f726d", ".aiff", "AIFF audio"),
    ("edabeedb", ".rpm",  "RPM package"),
    ("213c6172", ".ar",   "AR archive"),
    ("1fa0",     ".z",    "Compress .Z"),
    ("fefeff00", ".utf32","UTF-32 BE with BOM"),
    ("fffe0000", ".utf32","UTF-32 LE with BOM"),
    ("fffe",     ".utf16","UTF-16 LE with BOM"),
    ("feff",     ".utf16","UTF-16 BE with BOM"),
    ("efbbbf",   ".utf8", "UTF-8 with BOM"),
]

# PNG end-of-image marker
PNG_IEND = b"\x00\x00\x00\x00IEND\xaeB`\x82"
# JPEG end-of-image marker
JPEG_EOI = b"\xff\xd9"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok(msg):  print(f"  \033[92m[+]\033[0m {msg}")
def warn(msg): print(f"  \033[93m[!]\033[0m {msg}")
def fail(msg): print(f"  \033[91m[-]\033[0m {msg}")
def info(msg): print(f"  \033[94m[~]\033[0m {msg}")
def hdr(msg):  print(f"\n\033[1m── {msg} ──\033[0m")
def sep():     print("  " + "─" * 56)


def read_file(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    l = len(data)
    return -sum((c / l) * math.log2(c / l) for c in counts.values())


def is_printable(b: int) -> bool:
    return 0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d)


def highlight_flag(text: str) -> str:
    """ANSI-highlight any flag-like patterns in text."""
    def repl(m):
        return f"\033[93;1m{m.group(0)}\033[0m"
    return FLAG_RE.sub(repl, text)


# ---------------------------------------------------------------------------
# MAGIC BYTES
# ---------------------------------------------------------------------------

def detect_magic(data: bytes) -> list:
    matches = []
    hex_data = data[:16].hex()
    for magic_hex, ext, desc in MAGIC_DB:
        if hex_data.startswith(magic_hex):
            matches.append((ext, desc))
    return matches


def cmd_magic(args):
    hdr("MAGIC BYTES VS. EXTENSION")
    data = read_file(args.file)
    detected = detect_magic(data)
    ext = Path(args.file).suffix.lower()

    ok(f"File      : {args.file}")
    ok(f"Extension : {ext or '(none)'}")
    ok(f"First 16B : {data[:16].hex()}")
    ok(f"File size : {len(data):,} bytes")
    print()

    if detected:
        for det_ext, desc in detected:
            match = "✓ MATCHES extension" if det_ext == ext else f"⚠ MISMATCH — actually {desc}"
            print(f"  Magic → {desc} ({det_ext})  {match}")
            if det_ext != ext:
                warn(f"Extension says '{ext}' but magic says '{desc}' — file may be disguised!")
    else:
        warn("No known magic signature. File may be encrypted, obfuscated, or a raw data format.")
        info("Try: file command, binwalk, or hexdump manually")


# ---------------------------------------------------------------------------
# EXIF / METADATA
# ---------------------------------------------------------------------------

def cmd_exif(args):
    hdr("EXIF & METADATA EXTRACTION")
    data = read_file(args.file)

    # Use exiftool if available (best coverage)
    if shutil.which("exiftool"):
        info("Using exiftool:")
        r = subprocess.run(["exiftool", args.file], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if any(kw in line.lower() for kw in
                   ["comment", "description", "author", "copyright", "gps",
                    "artist", "title", "subject", "software", "note",
                    "usercomment", "imageuniqueid", "xmpdc"]):
                warn(f"  ★ {line.strip()}")
            else:
                print(f"    {line.strip()}")
        _flag_hunt_text(r.stdout, "exiftool output")
        return

    # Fallback: Pillow
    if not HAS_PIL:
        fail("Pillow not installed and exiftool not found. Run: pip install Pillow")
        return

    info("Using Pillow (install exiftool for full coverage):")
    try:
        img = Image.open(args.file)
        info(f"Format: {img.format}  Mode: {img.mode}  Size: {img.size}")

        # EXIF
        exif_data = img._getexif() if hasattr(img, "_getexif") else None
        if exif_data:
            for tag_id, value in exif_data.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                print(f"    {tag:<35} {str(value)[:100]}")
                _flag_hunt_text(str(value), f"EXIF tag {tag}")
        else:
            info("No EXIF data found (or not a JPEG/TIFF).")

        # Text chunks (PNG)
        if hasattr(img, "text") and img.text:
            hdr("PNG Text Chunks")
            for key, val in img.text.items():
                print(f"    {key}: {val[:200]}")
                _flag_hunt_text(val, f"PNG text chunk '{key}'")

        # Info dict
        if img.info:
            hdr("Image Info Dict")
            for k, v in img.info.items():
                print(f"    {k}: {str(v)[:200]}")

    except Exception as e:
        fail(f"Pillow error: {e}")


def _flag_hunt_text(text: str, source: str):
    for m in FLAG_RE.finditer(text):
        ok(f"FLAG candidate in {source}: {m.group(0)}")


# ---------------------------------------------------------------------------
# APPENDED DATA
# ---------------------------------------------------------------------------

def cmd_append(args):
    hdr("APPENDED DATA DETECTION")
    data = read_file(args.file)
    ext = Path(args.file).suffix.lower()

    eof_pos = None
    eof_marker = None

    if ext in (".png",):
        pos = data.rfind(PNG_IEND)
        if pos != -1:
            eof_pos = pos + len(PNG_IEND)
            eof_marker = "PNG IEND chunk"
    elif ext in (".jpg", ".jpeg"):
        pos = data.rfind(JPEG_EOI)
        if pos != -1:
            eof_pos = pos + len(JPEG_EOI)
            eof_marker = "JPEG EOI (FFD9)"
    elif ext in (".gif",):
        pos = data.rfind(b"\x3b")  # GIF trailer
        if pos != -1:
            eof_pos = pos + 1
            eof_marker = "GIF trailer (3B)"

    if eof_pos is None:
        # Generic: look for double EOF or unusual trailing bytes
        info("No format-specific EOF marker applied. Checking last 1KB for printable content.")
        trailing = data[-1024:]
        printable = sum(1 for b in trailing if is_printable(b))
        ratio = printable / len(trailing) if trailing else 0
        if ratio > 0.6:
            warn(f"High printable ratio in last 1KB ({ratio:.0%}) — may contain hidden text:")
            print(f"  {trailing.decode('utf-8', errors='replace')[:400]}")
        return

    ok(f"EOF marker : {eof_marker} at offset 0x{eof_pos:X}")
    ok(f"File size  : {len(data):,} bytes")
    appended_size = len(data) - eof_pos

    if appended_size <= 0:
        ok("No data appended after EOF marker.")
        return

    warn(f"APPENDED DATA FOUND: {appended_size:,} bytes after EOF!")
    appended = data[eof_pos:]
    entropy = shannon_entropy(appended)
    print(f"  Offset  : 0x{eof_pos:X} – 0x{len(data):X}")
    print(f"  Entropy : {entropy:.4f}  ({'encrypted/compressed' if entropy > 7.5 else 'readable'})")

    # Check for nested file magic
    inner_magic = detect_magic(appended)
    if inner_magic:
        warn(f"Embedded file detected: {inner_magic}")

    # Try to display as text
    try:
        as_text = appended.decode("utf-8", errors="strict")
        ok(f"Appended data is valid UTF-8:")
        print(f"  {highlight_flag(as_text[:500])}")
    except UnicodeDecodeError:
        info("Appended data is binary. First 64 bytes (hex):")
        print(f"  {appended[:64].hex()}")

    # Save
    if args.output:
        with open(args.output, "wb") as f:
            f.write(appended)
        ok(f"Saved appended bytes to: {args.output}")
    else:
        info(f"To save: python3 stego_triage.py append {args.file} -o appended.bin")


# ---------------------------------------------------------------------------
# LSB STEGANOGRAPHY
# ---------------------------------------------------------------------------

def cmd_lsb(args):
    hdr("LSB STEGANOGRAPHY ANALYSIS")

    if not HAS_PIL:
        fail("Pillow required: pip install Pillow")
        sys.exit(1)

    try:
        img = Image.open(args.file).convert("RGB")
    except Exception as e:
        fail(f"Cannot open image: {e}")
        sys.exit(1)

    pixels = list(img.getdata())
    width, height = img.size
    total_pixels = len(pixels)

    ok(f"Image: {width}x{height} px  ({total_pixels:,} pixels)")
    info(f"Extracting LSBs from R, G, B channels...")

    # Extract all LSBs from R, G, B channels
    def extract_lsb_bytes(channel_idx, n_bytes=256):
        bits = []
        for pixel in pixels:
            bits.append(pixel[channel_idx] & 1)
            if len(bits) >= n_bytes * 8:
                break
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            out.append(byte)
        return bytes(out)

    channel_names = ["R", "G", "B"]
    found_flags = []

    for ch_idx, ch_name in enumerate(channel_names):
        lsb_bytes = extract_lsb_bytes(ch_idx, n_bytes=512)
        printable = sum(1 for b in lsb_bytes if is_printable(b))
        ratio = printable / len(lsb_bytes) if lsb_bytes else 0

        try:
            text = lsb_bytes.decode("utf-8", errors="strict")
            is_text = True
        except UnicodeDecodeError:
            text = lsb_bytes.decode("utf-8", errors="replace")
            is_text = False

        print(f"\n  [{ch_name} channel LSB]  printable ratio: {ratio:.0%}")
        if ratio > 0.6:
            warn(f"  High printable ratio — likely contains text!")
            preview = text[:200].replace("\n", "↵").replace("\r", "")
            print(f"  Preview: {highlight_flag(preview)}")
            for m in FLAG_RE.finditer(text):
                ok(f"  FLAG in {ch_name} LSB: {m.group(0)}")
                found_flags.append(m.group(0))
        else:
            print(f"  First 32 bytes hex: {lsb_bytes[:32].hex()}")

    # Try combined RGB LSB (sequential R[0],G[0],B[0],R[1],G[1]...)
    print(f"\n  [Combined RGB LSB (sequential)]")
    bits = []
    for pixel in pixels[:2048]:
        for ch in range(3):
            bits.append(pixel[ch] & 1)
    combined = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = sum(bits[i+j] << (7-j) for j in range(8))
        combined.append(byte)

    try:
        combined_text = combined.decode("utf-8", errors="strict")
        printable = sum(1 for c in combined_text if c.isprintable())
        if printable / len(combined_text) > 0.6:
            ok(f"Combined RGB LSB looks like text:")
            print(f"  {highlight_flag(combined_text[:200])}")
    except UnicodeDecodeError:
        print(f"  First 32 bytes hex: {combined[:32].hex()}")

    if not found_flags:
        info("No obvious LSB flags found. Try stegsolve (GUI) or steghide for password-protected stego.")
        print("\n  Common stego tools to try manually:")
        print("  steghide extract -sf image.jpg -p ''            # empty password")
        print("  steghide extract -sf image.jpg -p 'password'    # known password")
        print("  stegseek image.jpg /usr/share/wordlists/rockyou.txt  # brute-force")
        print("  zsteg image.png                                   # multi-method PNG")
        print("  python3 ../flag_hunnter/flag_hunter.py image.png  # flag hunter")


# ---------------------------------------------------------------------------
# PNG CHUNK INSPECTOR
# ---------------------------------------------------------------------------

def cmd_chunks(args):
    hdr("PNG CHUNK INSPECTOR")
    data = read_file(args.file)

    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        fail("Not a PNG file (magic bytes mismatch)")
        sys.exit(1)

    ok(f"Valid PNG signature detected")
    pos = 8  # skip signature
    chunks = []

    while pos + 12 <= len(data):
        try:
            length = struct.unpack(">I", data[pos:pos+4])[0]
            chunk_type = data[pos+4:pos+8].decode("ascii", errors="replace")
            chunk_data = data[pos+8:pos+8+length]
            crc = data[pos+8+length:pos+12+length].hex()
            chunks.append((pos, chunk_type, length, chunk_data, crc))
            pos += 12 + length
        except Exception:
            break

    standard_chunks = {"IHDR","PLTE","IDAT","IEND","bKGD","cHRM","gAMA",
                        "hIST","iCCP","iTXt","pHYs","sBIT","sPLT","sRGB",
                        "tEXt","tIME","tRNS","zTXt"}

    print(f"\n  {'#':<4} {'TYPE':<8} {'SIZE':>10}  {'CRC':<10}  NOTE")
    print("  " + "─" * 60)

    for i, (offset, ctype, length, cdata, crc) in enumerate(chunks):
        is_nonstandard = ctype not in standard_chunks
        note = ""

        if is_nonstandard:
            note = "⚠ NON-STANDARD CHUNK"
        if ctype in ("tEXt", "zTXt", "iTXt"):
            note = "text metadata"
        if ctype == "iCCP":
            note = "embedded ICC profile"

        marker = "★ " if is_nonstandard else "  "
        print(f"  {i:<4} {ctype:<8} {length:>10,}  {crc:<10}  {marker}{note}")

        # Show text chunk content
        if ctype == "tEXt":
            try:
                null_pos = cdata.index(b"\x00")
                key = cdata[:null_pos].decode("latin-1")
                val = cdata[null_pos+1:].decode("latin-1", errors="replace")
                print(f"       Keyword: {key!r}")
                print(f"       Value:   {highlight_flag(val[:200])}")
                _flag_hunt_text(val, f"PNG tEXt chunk '{key}'")
            except Exception:
                pass

        if ctype == "iTXt":
            try:
                text = cdata.decode("utf-8", errors="replace")
                print(f"       iTXt: {highlight_flag(text[:300])}")
                _flag_hunt_text(text, "PNG iTXt chunk")
            except Exception:
                pass

        # Non-standard chunk — dump content
        if is_nonstandard and length > 0:
            try:
                text = cdata.decode("utf-8", errors="strict")
                warn(f"       Content (UTF-8): {highlight_flag(text[:300])}")
            except UnicodeDecodeError:
                warn(f"       Content (hex): {cdata[:32].hex()}")
            _flag_hunt_text(cdata.decode("utf-8", errors="replace"), f"chunk {ctype}")


# ---------------------------------------------------------------------------
# STRINGS
# ---------------------------------------------------------------------------

def cmd_strings(args):
    hdr("STRING EXTRACTION")
    data = read_file(args.file)
    min_len = args.min

    # Use system strings if available
    if shutil.which("strings"):
        info(f"Using system strings (min length {min_len}):")
        r = subprocess.run(
            ["strings", f"-n{min_len}", args.file],
            capture_output=True, text=True
        )
        output = r.stdout
        found_flags = []
        for line in output.splitlines():
            highlighted = highlight_flag(line)
            if highlighted != line:
                ok(f"★ {highlighted}")
                found_flags.append(line)
            elif args.all:
                print(f"  {line}")

        if found_flags:
            ok(f"\n{len(found_flags)} flag candidate(s) found in strings output")
        else:
            info("No flag patterns found. Use --all to see all strings.")
        return

    # Fallback: manual extraction
    result = []
    current = []
    for byte in data:
        if is_printable(byte):
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))

    for s in result:
        highlighted = highlight_flag(s)
        if highlighted != s:
            ok(f"★ {highlighted}")
        elif args.all:
            print(f"  {s}")


# ---------------------------------------------------------------------------
# BINWALK WRAPPER
# ---------------------------------------------------------------------------

def cmd_binwalk(args):
    hdr("BINWALK — EMBEDDED FILE DETECTION")

    if not shutil.which("binwalk"):
        fail("binwalk not found. Install: apt install binwalk")
        sys.exit(1)

    info(f"Running binwalk on: {args.file}")

    # Signature scan
    r = subprocess.run(
        ["binwalk", args.file],
        capture_output=True, text=True
    )
    print(r.stdout)

    if "0 " not in r.stdout and r.stdout.strip():
        # Found something — offer to extract
        ok("Embedded files/signatures found!")
        print(f"\n  To extract all embedded files:")
        print(f"  binwalk -e --run-as=root {args.file}")
        print(f"  # Extracted files will be in: _{Path(args.file).name}.extracted/")

        if args.extract:
            info("Extracting...")
            out_dir = args.extract
            r2 = subprocess.run(
                ["binwalk", "-e", f"--directory={out_dir}", args.file],
                capture_output=True, text=True
            )
            print(r2.stdout)
            if os.path.isdir(out_dir):
                extracted = list(Path(out_dir).rglob("*"))
                ok(f"Extracted {len(extracted)} items to {out_dir}")
                for item in extracted[:20]:
                    if item.is_file():
                        print(f"  {item}  ({item.stat().st_size:,} bytes)")
    else:
        warn("No embedded files found by binwalk.")
        info("Try: foremost, photorec, or scalpel for deep carving")


# ---------------------------------------------------------------------------
# FULL SCAN (auto triage)
# ---------------------------------------------------------------------------

def cmd_scan(args):
    print(f"\n\033[1m{'═'*64}\033[0m")
    print(f"\033[1m  STEGO TRIAGE: {args.file}\033[0m")
    print(f"\033[1m{'═'*64}\033[0m")

    data = read_file(args.file)
    ok(f"File size : {len(data):,} bytes")
    ok(f"Entropy   : {shannon_entropy(data):.4f} / 8.0")

    # 1. Magic bytes
    hdr("1. MAGIC BYTES")
    detected = detect_magic(data)
    ext = Path(args.file).suffix.lower()
    if detected:
        for det_ext, desc in detected:
            if det_ext != ext:
                warn(f"MISMATCH: extension={ext!r} but magic says {desc!r} — rename to {det_ext}")
            else:
                ok(f"OK: {desc}")
    else:
        warn("Unknown magic bytes — may be encrypted or obfuscated")

    # 2. Strings / flag hunt
    hdr("2. EMBEDDED STRINGS & FLAG HUNT")
    if shutil.which("strings"):
        r = subprocess.run(["strings", "-n8", args.file], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            for m in FLAG_RE.finditer(line):
                ok(f"FLAG IN STRINGS: {m.group(0)}")
    else:
        for m in FLAG_RE.finditer(data.decode("utf-8", errors="replace")):
            ok(f"FLAG: {m.group(0)}")

    # 3. Appended data
    hdr("3. APPENDED DATA AFTER EOF")
    _check_append_inline(data, ext)

    # 4. EXIF / metadata
    hdr("4. METADATA / EXIF")
    if shutil.which("exiftool"):
        r = subprocess.run(["exiftool", args.file], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if any(kw in line.lower() for kw in ["comment","description","author","gps","note","usercomment"]):
                warn(f"METADATA: {line.strip()}")
                for m in FLAG_RE.finditer(line):
                    ok(f"FLAG IN METADATA: {m.group(0)}")
    elif HAS_PIL:
        try:
            img = Image.open(args.file)
            if hasattr(img, "_getexif") and img._getexif():
                for tag_id, value in img._getexif().items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    for m in FLAG_RE.finditer(str(value)):
                        ok(f"FLAG IN EXIF ({tag}): {m.group(0)}")
        except Exception:
            pass
    else:
        warn("exiftool and Pillow both unavailable — skipping EXIF")

    # 5. PNG chunks
    if ext == ".png" and data.startswith(b"\x89PNG"):
        hdr("5. PNG CHUNK ANALYSIS")
        _check_png_chunks_inline(data)
    else:
        hdr("5. PNG CHUNKS — N/A (not a PNG)")
        info("Skipped")

    # 6. LSB analysis
    hdr("6. LSB STEGANOGRAPHY")
    if HAS_PIL and ext in (".png", ".bmp", ".jpg", ".jpeg"):
        _lsb_quick_check(args.file)
    else:
        warn("Pillow not available or not an image format — skipping LSB")
        info("Install: pip install Pillow")

    # 7. Binwalk
    hdr("7. BINWALK EMBEDDED FILE SCAN")
    if shutil.which("binwalk"):
        r = subprocess.run(["binwalk", args.file], capture_output=True, text=True)
        has_hits = any("DECIMAL" not in line and line.strip() and line[0].isdigit()
                        for line in r.stdout.splitlines())
        if has_hits:
            warn("Binwalk found embedded signatures!")
            for line in r.stdout.splitlines():
                if line.strip():
                    print(f"  {line}")
            print(f"\n  Extract: binwalk -e {args.file}")
        else:
            ok("No embedded files detected by binwalk")
    else:
        warn("binwalk not found — skipping")

    print(f"\n\033[1m{'═'*64}\033[0m")
    print("\033[1m  TRIAGE COMPLETE\033[0m")
    print(f"\033[1m{'═'*64}\033[0m")
    print("\n  If nothing found above, try:")
    print("  steghide extract -sf image.jpg -p ''")
    print("  stegseek image.jpg /usr/share/wordlists/rockyou.txt")
    print("  zsteg image.png  (gem install zsteg)")
    print(f"  python3 ../flag_hunnter/flag_hunter.py {args.file}")
    print(f"  python3 ../encoding_decoder/encoding_decoder.py scan {args.file}")


def _check_append_inline(data: bytes, ext: str):
    eof_pos = None
    marker_name = None

    if ext in (".png",) and data.rfind(PNG_IEND) != -1:
        eof_pos = data.rfind(PNG_IEND) + len(PNG_IEND)
        marker_name = "PNG IEND"
    elif ext in (".jpg", ".jpeg") and data.rfind(JPEG_EOI) != -1:
        eof_pos = data.rfind(JPEG_EOI) + len(JPEG_EOI)
        marker_name = "JPEG EOI"

    if eof_pos and eof_pos < len(data):
        appended = data[eof_pos:]
        warn(f"APPENDED DATA: {len(appended):,} bytes after {marker_name}!")
        try:
            text = appended.decode("utf-8", errors="strict")
            ok(f"Appended data (UTF-8): {highlight_flag(text[:300])}")
        except UnicodeDecodeError:
            info(f"Binary appended data — first 32 bytes: {appended[:32].hex()}")
            nested = detect_magic(appended)
            if nested:
                warn(f"Embedded file magic: {nested}")
    else:
        ok("No data appended after EOF marker")


def _check_png_chunks_inline(data: bytes):
    pos = 8
    standard = {"IHDR","PLTE","IDAT","IEND","bKGD","cHRM","gAMA","hIST",
                 "iCCP","iTXt","pHYs","sBIT","sPLT","sRGB","tEXt","tIME","tRNS","zTXt"}
    while pos + 12 <= len(data):
        try:
            length = struct.unpack(">I", data[pos:pos+4])[0]
            ctype = data[pos+4:pos+8].decode("ascii", errors="replace")
            cdata = data[pos+8:pos+8+length]
            if ctype not in standard:
                warn(f"Non-standard chunk: {ctype!r}  ({length:,} bytes)")
                try:
                    text = cdata.decode("utf-8", errors="strict")
                    ok(f"Content: {highlight_flag(text[:200])}")
                except UnicodeDecodeError:
                    info(f"Hex: {cdata[:32].hex()}")
            if ctype == "tEXt":
                try:
                    null_pos = cdata.index(b"\x00")
                    key = cdata[:null_pos].decode("latin-1")
                    val = cdata[null_pos+1:].decode("latin-1", errors="replace")
                    if val.strip():
                        info(f"tEXt chunk '{key}': {highlight_flag(val[:200])}")
                        for m in FLAG_RE.finditer(val):
                            ok(f"FLAG IN PNG TEXT: {m.group(0)}")
                except Exception:
                    pass
            pos += 12 + length
        except Exception:
            break


def _lsb_quick_check(path: str):
    try:
        img = Image.open(path).convert("RGB")
        pixels = list(img.getdata())
        # Quick check: extract R-channel LSBs
        bits = [p[0] & 1 for p in pixels[:4096]]
        out = bytearray()
        for i in range(0, len(bits)-7, 8):
            byte = sum(bits[i+j] << (7-j) for j in range(8))
            out.append(byte)
        try:
            text = out.decode("utf-8", errors="strict")
            printable = sum(1 for c in text if c.isprintable())
            if printable / len(text) > 0.7:
                warn(f"R-channel LSB looks like text (printable={printable/len(text):.0%}):")
                print(f"  {highlight_flag(text[:200])}")
                for m in FLAG_RE.finditer(text):
                    ok(f"FLAG IN LSB: {m.group(0)}")
                return
        except UnicodeDecodeError:
            pass
        info("LSB quick check: no obvious plaintext. Run 'lsb' subcommand for deep analysis.")
    except Exception as e:
        warn(f"LSB check failed: {e}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Steganography detection and file metadata triage for CTF"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_file(p):
        p.add_argument("file", help="Target image or file")
        return p

    p_scan = add_file(sub.add_parser("scan", help="Full automatic triage (start here)"))
    p_scan.add_argument("--all", action="store_true", help="Include verbose string output")

    add_file(sub.add_parser("magic",  help="Check magic bytes vs. file extension"))

    add_file(sub.add_parser("exif",   help="Extract EXIF and metadata"))

    p_append = add_file(sub.add_parser("append", help="Detect data appended after EOF"))
    p_append.add_argument("-o", "--output", help="Save appended bytes to this file")

    add_file(sub.add_parser("chunks", help="PNG chunk inspector"))

    p_lsb = add_file(sub.add_parser("lsb", help="LSB steganography detection + extraction"))
    p_lsb.add_argument("--all", action="store_true", help="Try all channel combinations")

    p_strings = add_file(sub.add_parser("strings", help="Extract printable strings"))
    p_strings.add_argument("--min", type=int, default=8, help="Minimum string length (default 8)")
    p_strings.add_argument("--all", action="store_true", help="Show all strings, not just flags")

    p_binwalk = add_file(sub.add_parser("binwalk", help="Binwalk embedded file detection"))
    p_binwalk.add_argument("--extract", help="Extract to this directory")

    args = parser.parse_args()

    if not os.path.isfile(args.file):
        fail(f"File not found: {args.file}")
        sys.exit(1)

    dispatch = {
        "scan": cmd_scan, "magic": cmd_magic, "exif": cmd_exif,
        "append": cmd_append, "chunks": cmd_chunks, "lsb": cmd_lsb,
        "strings": cmd_strings, "binwalk": cmd_binwalk,
    }
    try:
        dispatch[args.cmd](args)
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(0)


if __name__ == "__main__":
    main()
