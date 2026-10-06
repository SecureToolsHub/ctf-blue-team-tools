# zip_extracter

A specialized triage and preparation tool for encrypted ZIP archives (`ZipCrypto`), facilitating known-plaintext attacks using tools such as `bkcrack`.

## Features

- **Archive Inspection (`list`)**: Inspects ZIP file records, encryption flags, compression methods (Store vs Deflate), and internal CRC-32 checksums.
- **Known-Plaintext Generation (`gen-plaintext`)**: Generates candidate plaintext files for standard file types (PNG headers, XML wrappers, PDF headers).
- **Attack Command Suggestion (`suggest`)**: Recommends optimized `bkcrack` command-line syntax for attacking identified ZipCrypto entries.

## Usage

```bash
# List entries and encryption parameters in an archive
python3 zipcrypto_helper.py list archive.zip

# Generate synthetic known-plaintext file for target type
python3 zipcrypto_helper.py gen-plaintext archive.zip "image.png" --type png

# Generate bkcrack attack recommendations and command strings
python3 zipcrypto_helper.py suggest archive.zip -o ./bkcrack_workspace
```
