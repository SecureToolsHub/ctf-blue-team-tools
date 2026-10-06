# ad1_parser

A streaming forensic parser for **AccessData FTK Logical Images (`.ad1`)**. It enables rapid inspection, targeted pattern searching, and selective extraction of evidence files without mounting the container or requiring proprietary commercial software.

## Features

- **Streaming Architecture**: Efficiently parses multi-gigabyte AD1 containers with minimal memory footprint.
- **Pattern Matching**: Search file structures using regular expressions or case-insensitive keyword queries.
- **Selective Carving**: Extract target files or directories directly to disk while preserving folder hierarchy.
- **Zero Dependencies**: Pure Python 3 standard library implementation.

## Usage

```bash
# List all files and paths inside an AD1 image
python3 ad1_parser.py list /path/to/evidence.ad1

# Search for specific filenames or patterns
python3 ad1_parser.py search /path/to/evidence.ad1 --pattern ".*\.bash_history"
python3 ad1_parser.py search /path/to/evidence.ad1 --keyword "password"

# Extract files matching a pattern
python3 ad1_parser.py extract /path/to/evidence.ad1 --pattern "shadow$" -o ./extracted/
```
