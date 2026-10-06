#!/usr/bin/env python3
"""
code_doctor.py — Triage and repair broken source/config files so a
downed service can be relaunched.

What it does:
  1. Detects file type (by extension, falling back to shebang).
  2. Runs the appropriate syntax checker (python, php, node, bash,
     perl, ruby, json, yaml, xml, ini) if the interpreter is present.
  3. Detects common low-level breakage:
       - BOM markers, non-UTF8 encoding
       - CRLF/CR line endings mixed into a Unix file
       - mixed tabs/spaces indentation (Python's #1 killer)
       - trailing whitespace / missing final newline
       - unbalanced brackets/quotes (heuristic)
  4. In --apply mode, fixes the SAFE issues automatically and
     re-runs the syntax check to confirm the fix worked.
  5. Reports what's still broken so you know what to hand-edit.

This does not blindly rewrite logic — it repairs formatting/encoding
damage and tells you exactly what syntax error remains, so you can
fix the actual bug fast.

Usage:
    python3 code_doctor.py ./broken_app                 # dry-run report
    python3 code_doctor.py ./broken_app --apply          # fix + report
    python3 code_doctor.py app.py --tab-width 4 --apply
    python3 code_doctor.py --check-port 8080
    python3 code_doctor.py --check-service nginx
"""

import argparse
import configparser
import json
import os
import subprocess
import sys
import shutil
import socket
import xml.dom.minidom as minidom

EXT_LANG = {
    ".py": "python", ".php": "php", ".js": "javascript", ".mjs": "javascript",
    ".sh": "shell", ".bash": "shell", ".pl": "perl", ".rb": "ruby",
    ".json": "json", ".yml": "yaml", ".yaml": "yaml", ".xml": "xml",
    ".ini": "ini", ".conf": "ini", ".cfg": "ini",
}

SHEBANG_LANG = {
    "python": "python", "python3": "python", "php": "php", "node": "javascript",
    "bash": "shell", "sh": "shell", "perl": "perl", "ruby": "ruby",
}

# Files where tabs are semantically required — never touch indentation here.
TAB_SENSITIVE_NAMES = {"Makefile", "makefile", "GNUmakefile"}


def detect_language(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in EXT_LANG:
        return EXT_LANG[ext]
    try:
        with open(path, "rb") as f:
            first = f.readline(200).decode("utf-8", errors="ignore")
        if first.startswith("#!"):
            for key, lang in SHEBANG_LANG.items():
                if key in first:
                    return lang
    except Exception:
        pass
    return None


def tool_available(name):
    return shutil.which(name) is not None


def check_syntax(path, lang):
    """Return (ok: bool|None, message: str). ok=None means 'skipped'."""
    try:
        if lang == "python":
            r = subprocess.run([sys.executable, "-m", "py_compile", path],
                                capture_output=True, text=True)
            return (r.returncode == 0, r.stderr.strip() or "OK")

        if lang == "php":
            if not tool_available("php"):
                return (None, "php interpreter not found, skipped")
            r = subprocess.run(["php", "-l", path], capture_output=True, text=True)
            return (r.returncode == 0, (r.stdout + r.stderr).strip())

        if lang == "javascript":
            if not tool_available("node"):
                return (None, "node not found, skipped")
            r = subprocess.run(["node", "--check", path], capture_output=True, text=True)
            return (r.returncode == 0, r.stderr.strip() or "OK")

        if lang == "shell":
            shell = "bash" if tool_available("bash") else "sh"
            if not tool_available(shell):
                return (None, "no shell interpreter found, skipped")
            r = subprocess.run([shell, "-n", path], capture_output=True, text=True)
            return (r.returncode == 0, r.stderr.strip() or "OK")

        if lang == "perl":
            if not tool_available("perl"):
                return (None, "perl not found, skipped")
            r = subprocess.run(["perl", "-c", path], capture_output=True, text=True)
            return (r.returncode == 0, (r.stdout + r.stderr).strip())

        if lang == "ruby":
            if not tool_available("ruby"):
                return (None, "ruby not found, skipped")
            r = subprocess.run(["ruby", "-c", path], capture_output=True, text=True)
            return (r.returncode == 0, (r.stdout + r.stderr).strip())

        if lang == "json":
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                json.load(f)
            return (True, "OK")

        if lang == "yaml":
            try:
                import yaml
            except ImportError:
                return (None, "pyyaml not installed, skipped (pip install pyyaml)")
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                yaml.safe_load(f)
            return (True, "OK")

        if lang == "xml":
            minidom.parse(path)
            return (True, "OK")

        if lang == "ini":
            cp = configparser.ConfigParser()
            cp.read(path)
            return (True, "OK")

    except json.JSONDecodeError as e:
        return (False, f"JSON error: {e}")
    except configparser.Error as e:
        return (False, f"INI/config error: {e}")
    except Exception as e:
        return (False, f"{type(e).__name__}: {e}")

    return (None, "unknown file type, skipped")


def analyze_and_fix(path, tab_width, apply_fixes):
    """Return (issues: list[str], fixed: bool)."""
    issues = []
    basename = os.path.basename(path)
    is_tab_sensitive = basename in TAB_SENSITIVE_NAMES

    with open(path, "rb") as f:
        raw = f.read()

    had_bom = raw.startswith(b"\xef\xbb\xbf")
    if had_bom:
        raw = raw[3:]
        issues.append("UTF-8 BOM present")

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        issues.append("invalid UTF-8 bytes (replaced with U+FFFD)")

    had_crlf = "\r\n" in text
    had_cr_only = "\r" in text.replace("\r\n", "")
    if had_crlf:
        issues.append("CRLF line endings")
    if had_cr_only:
        issues.append("bare CR line endings")

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    mixed_indent = False
    trailing_ws = False
    if not is_tab_sensitive:
        for ln in lines:
            stripped = ln.rstrip("\n")
            leading = stripped[:len(stripped) - len(stripped.lstrip(" \t"))]
            if "\t" in leading and " " in leading:
                mixed_indent = True
            if stripped != stripped.rstrip():
                trailing_ws = True
    if mixed_indent:
        issues.append("mixed tabs/spaces indentation")
    if trailing_ws:
        issues.append("trailing whitespace")

    no_final_newline = len(text) > 0 and not text.endswith(("\n", "\r\n"))
    if no_final_newline:
        issues.append("missing final newline")

    # bracket/quote balance heuristic (informational only, not auto-fixed)
    for pair, name in [("(", "parentheses"), ("[", "brackets"), ("{", "braces")]:
        close = {"(": ")", "[": "]", "{": "}"}[pair]
        if text.count(pair) != text.count(close):
            issues.append(f"unbalanced {name} ({text.count(pair)} vs {text.count(close)})")

    if not issues:
        return issues, False

    if not apply_fixes:
        return issues, False

    fixed_lines = []
    for ln in lines:
        s = ln.rstrip()
        if not is_tab_sensitive and "\t" in s:
            s = s.expandtabs(tab_width)
        fixed_lines.append(s)
    fixed_text = "\n".join(fixed_lines)
    if not fixed_text.endswith("\n"):
        fixed_text += "\n"

    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(fixed_text)

    return issues, True


def iter_target_files(path):
    if os.path.isfile(path):
        yield path
    else:
        for root, _, files in os.walk(path):
            if ".git" in root.split(os.sep):
                continue
            for name in files:
                yield os.path.join(root, name)


def check_port(port, host="127.0.0.1"):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((host, port))
            return result == 0
    except Exception:
        return False


def check_systemd(name):
    if not tool_available("systemctl"):
        return None, "systemctl not available on this host"
    r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True)
    return (r.stdout.strip() == "active"), r.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description="Triage and repair broken source/config files")
    parser.add_argument("path", nargs="?", help="File or directory to scan")
    parser.add_argument("--apply", action="store_true",
                         help="Write safe fixes back to disk (default: dry-run report)")
    parser.add_argument("--tab-width", type=int, default=4)
    parser.add_argument("--check-port", type=int, help="Check if a local port is open")
    parser.add_argument("--check-service", help="Check a systemd service's status")
    args = parser.parse_args()

    if args.check_port is not None:
        up = check_port(args.check_port)
        print(f"port {args.check_port}: {'OPEN' if up else 'closed/unreachable'}")

    if args.check_service:
        active, detail = check_systemd(args.check_service)
        if active is None:
            print(f"service {args.check_service}: {detail}")
        else:
            print(f"service {args.check_service}: {'ACTIVE' if active else 'INACTIVE'} ({detail})")

    if not args.path:
        if args.check_port is None and not args.check_service:
            parser.print_help()
        return

    if not os.path.exists(args.path):
        print(f"Path not found: {args.path}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*70}")
    print(f"{'APPLYING FIXES' if args.apply else 'DRY-RUN REPORT'}: {args.path}")
    print(f"{'='*70}")

    total, broken, fixed_count = 0, 0, 0

    for f in sorted(iter_target_files(args.path)):
        lang = detect_language(f)
        if lang is None:
            continue
        total += 1

        issues, was_fixed = analyze_and_fix(f, args.tab_width, args.apply)
        ok, msg = check_syntax(f, lang)

        status = "OK" if ok else ("SKIP" if ok is None else "BROKEN")
        if ok is False:
            broken += 1
        if was_fixed:
            fixed_count += 1

        rel = os.path.relpath(f, os.path.dirname(args.path) or ".")
        print(f"\n[{status}] {rel}  ({lang})")
        if issues:
            print(f"   issues: {', '.join(issues)}" +
                  ("  -> fixed" if was_fixed else ""))
        if ok is False:
            print(f"   syntax error: {msg}")
        elif ok is None:
            print(f"   note: {msg}")

    print(f"\n{'-'*70}")
    print(f"Scanned {total} recognizable file(s). "
          f"{broken} still broken. {fixed_count} file(s) auto-fixed.")
    if not args.apply and (fixed_count == 0 and total):
        print("Run again with --apply to write safe fixes to disk.")


if __name__ == "__main__":
    main()
