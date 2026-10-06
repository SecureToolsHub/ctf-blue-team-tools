# hash_toolkit

A comprehensive cryptographic hash utility for incident response, malware analysis, and CTF challenges.

## Features

- **Hash Calculation**: Computes MD5, SHA-1, SHA-256, and SHA-512 hashes for input strings or binary files.
- **Hash Identification**: Identifies probable hash algorithms from string format, length, and character set (NTLM, MySQL, Django, bcrypt, SHA-crypt, MD5).
- **Wordlist Verification**: Rapidly tests a target hash against password dictionaries or custom wordlists.

## Usage

```bash
# Calculate hashes for a file or string
python3 hash_toolkit.py hash /path/to/suspicious_binary
python3 hash_toolkit.py hash --string "admin123"

# Identify the algorithm of an unknown hash string
python3 hash_toolkit.py identify "5f4dcc3b5aa765d61d8327deb882cf99"

# Crack / verify a hash using a dictionary list
python3 hash_toolkit.py crack "5f4dcc3b5aa765d61d8327deb882cf99" --wordlist /usr/share/wordlists/rockyou.txt
```
