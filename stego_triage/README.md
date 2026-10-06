# stego_triage

An automated steganography detection and file triage tool designed to uncover hidden data in multimedia and binary files.

## Features

- **File Header Verification (`magic`)**: Validates real file magic bytes against the declared file extension to identify disguised executables or archives.
- **Appended Data Extraction (`trailing`)**: Detects and extracts data appended beyond the official End of File (EOF) marker (e.g. PK zip archives appended to JPEG/PNG).
- **Embedded Strings (`strings`)**: Extracts ASCII/Unicode strings with custom length filtering and regex pattern matching.
- **LSB Analysis (`lsb`)**: Inspects Least Significant Bit channels in image files for hidden payloads.

## Usage

```bash
# Run full automated stego triage on an image or binary
python3 stego_triage.py scan image.png

# Check magic bytes vs extension
python3 stego_triage.py magic suspicious.jpg

# Inspect and carve trailing appended payload
python3 stego_triage.py trailing image.png --extract -o ./carved/

# Analyze LSB channels for hidden data
python3 stego_triage.py lsb image.png
```
