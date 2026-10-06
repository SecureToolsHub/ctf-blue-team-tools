#!/usr/bin/env python3
"""
hash_toolkit.py — Hash identification, cracking command generator, and
batch processor for Blue Team CTF competitions.

Found a hash in a log, database dump, shadow file, or SIEM alert?
This tool identifies the type and gives you the exact hashcat/john command
to crack it — including the right mode number and wordlist path.

Subcommands:
  identify   Identify hash type(s) from a string or file
  crack      Generate hashcat + john commands to crack a hash
  batch      Process a file of hashes (one per line) — identify + suggest crack
  verify     Check if a plaintext matches a hash (any supported type)
  shadow     Parse /etc/shadow and identify all hash types
  wordlist   Show available wordlists on this system

Usage:
    python3 hash_toolkit.py identify "5f4dcc3b5aa765d61d8327deb882cf99"
    python3 hash_toolkit.py identify hashes.txt
    python3 hash_toolkit.py crack "5f4dcc3b5aa765d61d8327deb882cf99"
    python3 hash_toolkit.py crack "$2b$12$..." --wordlist /usr/share/wordlists/rockyou.txt
    python3 hash_toolkit.py batch hashes.txt -o cracking_session.sh
    python3 hash_toolkit.py verify "5f4dcc3b5aa765d61d8327deb882cf99" "password"
    python3 hash_toolkit.py shadow /etc/shadow
    python3 hash_toolkit.py wordlist
"""

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Hash signature database
# ---------------------------------------------------------------------------
# Each entry: (name, hashcat_mode, regex, length_hint, example, notes)

HASH_DB = [
    # ── Crypto / Login Hashes ──────────────────────────────────────────────
    {
        "name": "MD5",
        "mode": 0,
        "john_format": "raw-md5",
        "regex": re.compile(r"^[a-fA-F0-9]{32}$"),
        "example": "5f4dcc3b5aa765d61d8327deb882cf99",
        "notes": "Most common. 32 hex chars.",
    },
    {
        "name": "MD5(Unix / $1$)",
        "mode": 500,
        "john_format": "md5crypt",
        "regex": re.compile(r"^\$1\$[./a-zA-Z0-9]{1,8}\$[./a-zA-Z0-9]{22}$"),
        "example": "$1$salt$hash",
        "notes": "Linux /etc/shadow MD5 crypt.",
    },
    {
        "name": "SHA-1",
        "mode": 100,
        "john_format": "raw-sha1",
        "regex": re.compile(r"^[a-fA-F0-9]{40}$"),
        "example": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "notes": "40 hex chars.",
    },
    {
        "name": "SHA-256",
        "mode": 1400,
        "john_format": "raw-sha256",
        "regex": re.compile(r"^[a-fA-F0-9]{64}$"),
        "example": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "notes": "64 hex chars.",
    },
    {
        "name": "SHA-512",
        "mode": 1700,
        "john_format": "raw-sha512",
        "regex": re.compile(r"^[a-fA-F0-9]{128}$"),
        "example": "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86",
        "notes": "128 hex chars.",
    },
    {
        "name": "SHA-512(Unix / $6$)",
        "mode": 1800,
        "john_format": "sha512crypt",
        "regex": re.compile(r"^\$6\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}$"),
        "example": "$6$salt$hash",
        "notes": "Linux /etc/shadow SHA-512 crypt. Modern default.",
    },
    {
        "name": "SHA-256(Unix / $5$)",
        "mode": 7400,
        "john_format": "sha256crypt",
        "regex": re.compile(r"^\$5\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{43}$"),
        "example": "$5$salt$hash",
        "notes": "Linux /etc/shadow SHA-256 crypt.",
    },
    {
        "name": "bcrypt ($2a$ / $2b$ / $2y$)",
        "mode": 3200,
        "john_format": "bcrypt",
        "regex": re.compile(r"^\$2[aby]\$\d{2}\$[./a-zA-Z0-9]{53}$"),
        "example": "$2b$12$...",
        "notes": "Very slow to crack. Common in web apps (PHP, Django, etc.).",
    },
    {
        "name": "NTLM",
        "mode": 1000,
        "john_format": "nt",
        "regex": re.compile(r"^[a-fA-F0-9]{32}$"),
        "example": "8846f7eaee8fb117ad06bdd830b7586c",
        "notes": "Same length as MD5. Context (e.g. SAM/NTDS) distinguishes them.",
    },
    {
        "name": "LM Hash",
        "mode": 3000,
        "john_format": "lm",
        "regex": re.compile(r"^[a-fA-F0-9]{32}$"),
        "example": "e52cac67419a9a224a3b108f3fa6cb6d",
        "notes": "Old Windows LAN Manager hash. Extremely weak.",
    },
    {
        "name": "Net-NTLMv1",
        "mode": 5500,
        "john_format": "netntlm",
        "regex": re.compile(r"^.+::.+:[a-fA-F0-9]{48}:[a-fA-F0-9]{32}:[a-fA-F0-9]{16}$"),
        "example": "user::domain:challenge:response:response2",
        "notes": "Captured via Responder/MITM. From network.",
    },
    {
        "name": "Net-NTLMv2",
        "mode": 5600,
        "john_format": "netntlmv2",
        "regex": re.compile(r"^.+::.+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$"),
        "example": "user::domain:challenge:response:blob",
        "notes": "Modern Windows challenge-response. From Responder.",
    },
    {
        "name": "WPA/WPA2 Handshake",
        "mode": 22000,
        "john_format": "wpapsk",
        "regex": re.compile(r"^[a-fA-F0-9]{64}\*"),
        "example": "PMKID or hccapx",
        "notes": "Use hcxtools to convert pcap → hccapx first.",
    },
    {
        "name": "MD4",
        "mode": 900,
        "john_format": "raw-md4",
        "regex": re.compile(r"^[a-fA-F0-9]{32}$"),
        "example": "31d6cfe0d16ae931b73c59d7e0c089c0",
        "notes": "Same length as MD5/NTLM. Rare in modern apps.",
    },
    {
        "name": "MySQL4.1+ password hash",
        "mode": 300,
        "john_format": "mysql-sha1",
        "regex": re.compile(r"^\*[a-fA-F0-9]{40}$"),
        "example": "*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9",
        "notes": "MySQL password() function (MySQL 4.1+). Starts with *.",
    },
    {
        "name": "MySQL OLD password hash",
        "mode": 200,
        "john_format": "mysql",
        "regex": re.compile(r"^[a-fA-F0-9]{16}$"),
        "example": "606717496665bcba",
        "notes": "Old MySQL password() — 16 hex chars.",
    },
    {
        "name": "Argon2",
        "mode": None,
        "john_format": "argon2",
        "regex": re.compile(r"^\$argon2[id]+\$"),
        "example": "$argon2id$v=19$m=65536...",
        "notes": "Modern KDF. hashcat support limited — use john.",
    },
    {
        "name": "PBKDF2-SHA256 (Django)",
        "mode": 10000,
        "john_format": "django",
        "regex": re.compile(r"^pbkdf2_sha256\$"),
        "example": "pbkdf2_sha256$260000$...",
        "notes": "Django default password hasher.",
    },
    {
        "name": "Django (SHA1)",
        "mode": 124,
        "john_format": "django",
        "regex": re.compile(r"^sha1\$.+\$[a-fA-F0-9]{40}$"),
        "example": "sha1$salt$hash",
        "notes": "Old Django SHA1 hashed password.",
    },
    {
        "name": "Base64-encoded hash",
        "mode": None,
        "john_format": None,
        "regex": re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"),
        "example": "X2tveW91cl9oYXNo",
        "notes": "Decode first: echo 'HASH' | base64 -d | xxd",
    },
    {
        "name": "CRC32",
        "mode": 11500,
        "john_format": None,
        "regex": re.compile(r"^[a-fA-F0-9]{8}$"),
        "example": "2ef8cf31",
        "notes": "8 hex chars. Very weak.",
    },
    {
        "name": "Kerberos 5 TGS (etype 23)",
        "mode": 13100,
        "john_format": "krb5tgs",
        "regex": re.compile(r"^\$krb5tgs\$23\$"),
        "example": "$krb5tgs$23$*user*...",
        "notes": "Kerberoasting output from Impacket/Rubeus.",
    },
    {
        "name": "Kerberos 5 AS-REP (etype 23)",
        "mode": 18200,
        "john_format": "krb5asrep",
        "regex": re.compile(r"^\$krb5asrep\$23\$"),
        "example": "$krb5asrep$23$...",
        "notes": "AS-REP roasting output.",
    },
]


COMMON_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "/usr/share/seclists/Passwords/rockyou-75.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/best1050.txt",
    "/opt/wordlists/rockyou.txt",
    "/root/rockyou.txt",
    "~/wordlists/rockyou.txt",
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ok(msg):  print(f"\033[92m[+]\033[0m {msg}")
def warn(msg): print(f"\033[93m[!]\033[0m {msg}")
def info(msg): print(f"\033[94m[~]\033[0m {msg}")
def fail(msg): print(f"\033[91m[-]\033[0m {msg}")
def hdr(msg):  print(f"\n\033[1m{'─'*60}\n  {msg}\n{'─'*60}\033[0m")


def find_wordlist(preferred=None):
    if preferred and os.path.isfile(preferred):
        return preferred
    for wl in COMMON_WORDLISTS:
        expanded = os.path.expanduser(wl)
        if os.path.isfile(expanded):
            return expanded
    return None


def identify_hash(h: str) -> list:
    h = h.strip()
    matches = []
    for entry in HASH_DB:
        if entry["regex"].match(h):
            matches.append(entry)
    return matches


# ---------------------------------------------------------------------------
# IDENTIFY
# ---------------------------------------------------------------------------

def cmd_identify(args):
    hdr("HASH IDENTIFICATION")
    hashes = _load_hashes(args.hash_or_file)

    for h in hashes:
        h = h.strip()
        if not h or h.startswith("#"):
            continue
        matches = identify_hash(h)
        print(f"\n  Hash: {h[:80]}{'...' if len(h)>80 else ''}")
        print(f"  Len:  {len(h)}")
        if not matches:
            warn("  Unknown hash type — try: hash-identifier or hashid")
        else:
            for m in matches:
                mode_str = f"hashcat -m {m['mode']}" if m["mode"] is not None else "hashcat N/A"
                print(f"  ✓ {m['name']}")
                print(f"    {mode_str}  |  john --format={m['john_format'] or 'auto'}")
                print(f"    Notes: {m['notes']}")


def _load_hashes(hash_or_file: str) -> list:
    if os.path.isfile(hash_or_file):
        with open(hash_or_file) as f:
            return [line.strip() for line in f if line.strip()]
    return [hash_or_file]


# ---------------------------------------------------------------------------
# CRACK
# ---------------------------------------------------------------------------

def cmd_crack(args):
    hdr("CRACK COMMAND GENERATOR")
    h = args.hash_value.strip()
    matches = identify_hash(h)

    wordlist = find_wordlist(args.wordlist)
    wl_str = wordlist or "/path/to/wordlist.txt"
    if not wordlist:
        warn("No wordlist found automatically. Common locations:")
        for wl in COMMON_WORDLISTS[:5]:
            print(f"  {wl}")

    hashcat_bin = shutil.which("hashcat") or "hashcat"
    john_bin    = shutil.which("john") or "john"

    # Write hash to temp file for commands
    hash_file = "/tmp/ctf_hash.txt"

    print(f"\n  Hash  : {h[:80]}")
    print(f"  Length: {len(h)}\n")

    if not matches:
        warn("Hash type not recognized automatically.")
        print("  Run: hash-identifier, hashid, or name-that-hash for manual analysis")
        print(f"\n  Generic hashcat brute-force (auto-detect):")
        print(f"  echo '{h}' > {hash_file}")
        print(f"  {hashcat_bin} -a 0 {hash_file} {wl_str}")
        return

    for m in matches:
        print(f"{'═'*60}")
        print(f"  Type: {m['name']}")
        print(f"  Notes: {m['notes']}")
        print()

        # Save hash
        print(f"  # 1. Save hash:")
        print(f"  echo '{h}' > {hash_file}")
        print()

        if m["mode"] is not None:
            # Hashcat dictionary attack
            print(f"  # 2a. Hashcat — dictionary attack:")
            print(f"  {hashcat_bin} -m {m['mode']} -a 0 {hash_file} {wl_str}")
            print()

            # Hashcat rules attack
            rules = "/usr/share/hashcat/rules/best64.rule"
            print(f"  # 2b. Hashcat — rules attack (better coverage):")
            print(f"  {hashcat_bin} -m {m['mode']} -a 0 {hash_file} {wl_str} -r {rules}")
            print()

            # Hashcat brute-force (mask attack) for short passwords
            print(f"  # 2c. Hashcat — brute-force up to 8 chars:")
            print(f"  {hashcat_bin} -m {m['mode']} -a 3 {hash_file} ?a?a?a?a?a?a?a?a --increment")
            print()

        if m["john_format"]:
            print(f"  # 3. John the Ripper:")
            print(f"  {john_bin} --format={m['john_format']} --wordlist={wl_str} {hash_file}")
            print(f"  {john_bin} --format={m['john_format']} --show {hash_file}  # show cracked")
            print()

        # Special instructions per type
        _special_instructions(m, h, hashcat_bin, wl_str)


def _special_instructions(m, h, hashcat_bin, wl_str):
    name = m["name"]
    if "bcrypt" in name.lower():
        warn("bcrypt is slow. On GPU: ~20K/s. CPU only: ~200/s. Use short wordlist.")
    elif "NTLM" in name and "Net-" not in name:
        info("NTLM hashes often crack quickly — try common passwords first.")
        info("Extract from SAM: secretsdump.py or mimikatz lsadump::sam")
    elif "Net-NTLMv2" in name:
        info("Capture with: Responder -I eth0 -wrf")
        info(f"Then: {hashcat_bin} -m 5600 {h[:30]}... {wl_str}")
    elif "Kerberos" in name:
        info("Kerberoasting: GetUserSPNs.py -request -dc-ip <DC> domain/user:pass")
        info("AS-REP Roasting: GetNPUsers.py domain/ -usersfile users.txt -no-pass")
    elif "WPA" in name:
        info("Convert pcap: hcxpcapngtool -o hashes.hc22000 capture.pcap")
        info(f"Then: {hashcat_bin} -m 22000 hashes.hc22000 {wl_str}")
    elif "shadow" in name.lower() or "Unix" in name:
        info("Extract from shadow: sudo cat /etc/shadow | cut -d: -f2 > shadow_hashes.txt")
    elif "MySQL" in name:
        info("Extract: SELECT user, authentication_string FROM mysql.user;")
    elif "Django" in name:
        info("Extract from DB: SELECT username, password FROM auth_user;")


# ---------------------------------------------------------------------------
# BATCH
# ---------------------------------------------------------------------------

def cmd_batch(args):
    hdr("BATCH HASH PROCESSING")

    if not os.path.isfile(args.file):
        fail(f"File not found: {args.file}")
        sys.exit(1)

    wordlist = find_wordlist(args.wordlist)
    wl_str = wordlist or "/path/to/wordlist.txt"
    hashcat_bin = shutil.which("hashcat") or "hashcat"
    john_bin = shutil.which("john") or "john"

    # Group hashes by identified type
    grouped = {}  # mode -> (name, john_format, [hashes])
    unknown = []

    with open(args.file) as f:
        for line in f:
            h = line.strip()
            if not h or h.startswith("#"):
                continue
            matches = identify_hash(h)
            if not matches:
                unknown.append(h)
                continue
            m = matches[0]  # use first match
            key = m["mode"]
            if key not in grouped:
                grouped[key] = {"name": m["name"], "john_format": m["john_format"], "hashes": []}
            grouped[key]["hashes"].append(h)

    total = sum(len(v["hashes"]) for v in grouped.values()) + len(unknown)
    ok(f"Processed {total} hashes → {len(grouped)} type(s) identified, {len(unknown)} unknown\n")

    script_lines = ["#!/bin/bash", "# Auto-generated cracking script by hash_toolkit.py", ""]
    results = []

    for mode, data in sorted(grouped.items(), key=lambda x: str(x[0])):
        name = data["name"]
        hashes = data["hashes"]
        john_fmt = data["john_format"]

        hash_file = f"/tmp/hashes_mode{mode}.txt"
        print(f"  [{name}]  {len(hashes)} hash(es)  mode={mode}")
        for h in hashes[:5]:
            print(f"    {h[:72]}")
        if len(hashes) > 5:
            print(f"    ... +{len(hashes)-5} more")
        print()

        script_lines.append(f"# ── {name} (mode {mode}) ──")
        script_lines.append(f"printf '%s\\n' {' '.join(repr(h) for h in hashes)} > {hash_file}")
        if mode is not None:
            script_lines.append(f"{hashcat_bin} -m {mode} -a 0 {hash_file} {wl_str}")
            script_lines.append(f"{hashcat_bin} -m {mode} --show {hash_file}  # show results")
        if john_fmt:
            script_lines.append(f"{john_bin} --format={john_fmt} --wordlist={wl_str} {hash_file}")
        script_lines.append("")
        results.append((name, mode, hash_file))

    if unknown:
        warn(f"{len(unknown)} unrecognized hashes:")
        for h in unknown[:10]:
            print(f"    {h[:80]}")
        script_lines.append("# ── Unknown hashes ──")
        for h in unknown:
            script_lines.append(f"# {h}")

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(script_lines) + "\n")
        os.chmod(args.output, 0o755)
        ok(f"Cracking script saved to: {args.output}")
        info(f"Run it with: bash {args.output}")


# ---------------------------------------------------------------------------
# VERIFY
# ---------------------------------------------------------------------------

def cmd_verify(args):
    hdr("HASH VERIFICATION")
    h = args.hash_value.strip()
    plaintext = args.plaintext.encode()

    # Try common algorithms
    checks = [
        ("MD5",    hashlib.md5(plaintext).hexdigest()),
        ("SHA-1",  hashlib.sha1(plaintext).hexdigest()),
        ("SHA-256",hashlib.sha256(plaintext).hexdigest()),
        ("SHA-512",hashlib.sha512(plaintext).hexdigest()),
        ("SHA-224",hashlib.sha224(plaintext).hexdigest()),
        ("SHA-384",hashlib.sha384(plaintext).hexdigest()),
    ]

    matched = False
    for algo, digest in checks:
        if digest.lower() == h.lower():
            ok(f"MATCH: {algo}('{args.plaintext}') = {digest}")
            matched = True

    # Try passlib for bcrypt / unix crypt
    try:
        from passlib.hash import (bcrypt, sha512_crypt, sha256_crypt,
                                   md5_crypt, des_crypt)
        for algo, handler in [("bcrypt", bcrypt), ("sha512crypt", sha512_crypt),
                               ("sha256crypt", sha256_crypt), ("md5crypt", md5_crypt)]:
            try:
                if handler.verify(args.plaintext, h):
                    ok(f"MATCH: {algo}('{args.plaintext}') verified against {h[:30]}...")
                    matched = True
            except Exception:
                pass
    except ImportError:
        pass

    # NTLM
    ntlm = hashlib.new("md4", plaintext.decode("utf-8").encode("utf-16-le")).hexdigest()
    if ntlm.lower() == h.lower():
        ok(f"MATCH: NTLM('{args.plaintext}') = {ntlm}")
        matched = True

    if not matched:
        fail(f"No match found for plaintext '{args.plaintext}' against hash '{h[:40]}...'")


# ---------------------------------------------------------------------------
# SHADOW PARSER
# ---------------------------------------------------------------------------

def cmd_shadow(args):
    hdr("SHADOW FILE ANALYSIS")
    shadow_path = args.shadow_file

    if not os.path.isfile(shadow_path):
        fail(f"File not found: {shadow_path}")
        sys.exit(1)

    hashes = []
    with open(shadow_path) as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 2:
                continue
            user, pw_hash = parts[0], parts[1]
            if pw_hash in ("*", "!", "!!") or not pw_hash:
                continue
            hashes.append((user, pw_hash))

    ok(f"Found {len(hashes)} active password hash(es):\n")
    grouped = {}
    for user, h in hashes:
        matches = identify_hash(h)
        name = matches[0]["name"] if matches else "Unknown"
        mode = matches[0]["mode"] if matches else None
        grouped.setdefault(name, []).append((user, h))
        print(f"  {user:<20} [{name}]  {h[:60]}")

    print(f"\n── Cracking commands ──")
    wordlist = find_wordlist(None)
    wl_str = wordlist or "/usr/share/wordlists/rockyou.txt"
    hashcat_bin = shutil.which("hashcat") or "hashcat"
    john_bin = shutil.which("john") or "john"

    for name, users in grouped.items():
        print(f"\n  # {name}:")
        hash_file = f"/tmp/shadow_hashes.txt"
        print(f"  grep -v '^#' {shadow_path} | cut -d: -f2 | grep -v '^[!*]' > {hash_file}")
        matches = identify_hash(users[0][1])
        if matches and matches[0]["mode"] is not None:
            mode = matches[0]["mode"]
            jfmt = matches[0].get("john_format", "auto")
            print(f"  {hashcat_bin} -m {mode} -a 0 {hash_file} {wl_str}")
            print(f"  {john_bin} --format={jfmt} --wordlist={wl_str} {shadow_path}")
            print(f"  {john_bin} --format={jfmt} --show {shadow_path}")


# ---------------------------------------------------------------------------
# WORDLIST
# ---------------------------------------------------------------------------

def cmd_wordlist(_args):
    hdr("AVAILABLE WORDLISTS")
    found_any = False
    for wl in COMMON_WORDLISTS:
        expanded = os.path.expanduser(wl)
        if os.path.isfile(expanded):
            size = os.path.getsize(expanded)
            try:
                count = int(subprocess.check_output(["wc", "-l", expanded]).split()[0])
            except Exception:
                count = -1
            ok(f"{expanded}")
            print(f"     size={size:,} bytes  lines={count:,}")
            found_any = True

    if not found_any:
        warn("No common wordlists found.")
        print("\n  Install with:")
        print("  apt install wordlists                         # Kali")
        print("  gzip -d /usr/share/wordlists/rockyou.txt.gz  # if gzipped")

    print("\n── Custom wordlist tips ──")
    print("  # Combine and sort:")
    print("  cat wordlist1.txt wordlist2.txt | sort -u > combined.txt")
    print()
    print("  # Generate from website keywords (cewl):")
    print("  cewl http://target.com -d 3 -m 5 -w custom.txt")
    print()
    print("  # Expand with rules (hashcat rule-based mutations):")
    print("  hashcat -m 0 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Hash identification and crack-command generator for CTF"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("identify", help="Identify hash type(s)")
    p_id.add_argument("hash_or_file", help="A hash string, or path to a file of hashes")

    p_crack = sub.add_parser("crack", help="Generate hashcat + john cracking commands")
    p_crack.add_argument("hash_value", help="Hash string to crack")
    p_crack.add_argument("--wordlist", "-w", help="Path to wordlist (auto-detected if omitted)")

    p_batch = sub.add_parser("batch", help="Process a file of hashes — identify + script")
    p_batch.add_argument("file", help="File with one hash per line")
    p_batch.add_argument("--wordlist", "-w")
    p_batch.add_argument("-o", "--output", help="Write cracking shell script to this file")

    p_verify = sub.add_parser("verify", help="Check if plaintext matches a hash")
    p_verify.add_argument("hash_value")
    p_verify.add_argument("plaintext")

    p_shadow = sub.add_parser("shadow", help="Parse /etc/shadow and generate crack commands")
    p_shadow.add_argument("shadow_file", help="Path to shadow file (use /etc/shadow or extracted copy)")

    sub.add_parser("wordlist", help="Show available wordlists on this system")

    args = parser.parse_args()
    dispatch = {
        "identify": cmd_identify,
        "crack": cmd_crack,
        "batch": cmd_batch,
        "verify": cmd_verify,
        "shadow": cmd_shadow,
        "wordlist": cmd_wordlist,
    }
    try:
        dispatch[args.cmd](args)
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(0)


if __name__ == "__main__":
    main()
