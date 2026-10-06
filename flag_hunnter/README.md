# flag_hunnter

A dual-purpose toolkit for CTF competitions and forensic artifact hunting, featuring flag search pattern matching and binary entropy visualization.

## Components

- **`flag_hunter.py`**: High-performance recursive scanner that searches files, memory dumps, and SQL databases for competition flags, tokens, and challenge strings matching specific prefixes or regular expressions.
- **`entropy_scan.py`**: Shannon entropy calculation tool that scans binary images and data dumps in blocks to locate encrypted, compressed, or obfuscated payloads.

## Usage

### Flag Hunter
```bash
# Scan a directory or file using default common prefixes (ctf, flag, cyberkent)
python3 flag_hunter.py /path/to/evidence

# Search with custom flag prefixes or regex pattern
python3 flag_hunter.py /path/to/evidence --prefixes ctf,flag,HTB,THM
python3 flag_hunter.py /path/to/evidence --pattern "FLAG\{[a-zA-Z0-9_-]+\}"
```

### Entropy Scanner
```bash
# High-level coarse entropy scan across a large binary dump
python3 entropy_scan.py evidence.bin --rows 100

# High-resolution targeted entropy analysis across a specific byte range
python3 entropy_scan.py evidence.bin --start 0x1000 --end 0x50000 --block-size 4096
```
