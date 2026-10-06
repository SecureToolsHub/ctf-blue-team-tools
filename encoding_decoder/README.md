# encoding_decoder

A multi-format data decoder and cipher analysis tool built to handle obfuscated payloads, CTF artifacts, and network strings.

## Features

- **Multi-Format Support**: Decodes Base64, Hexadecimal, URL-encoding, Binary (bits), ROT13, and single-byte XOR.
- **Recursive Auto-Decode (`auto`)**: Automatically analyzes and recursively unravels nested multi-stage encodings (e.g. Base64 inside Hex inside URL).
- **Brute-Force XOR**: Tests all 256 single-byte XOR keys and scores output against printable English/ASCII heuristics.

## Usage

```bash
# Automatically detect and recursively peel multi-layer encodings
python3 encoding_decoder.py auto "VTJobGJtZDFjR1JsWTNSeQ=="

# Manual decoding for specific schemes
python3 encoding_decoder.py base64 "SGVsbG8gV29ybGQ="
python3 encoding_decoder.py hex "48656c6c6f"
python3 encoding_decoder.py rot13 "Uryyb"

# Single-byte XOR brute-force analysis
python3 encoding_decoder.py xor-brute "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
```
