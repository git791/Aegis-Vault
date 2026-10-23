# Aegis Vault

**A local-first file encryption vault with a built-in AES teaching lab.**
Team 1: Amiya, Krrish, Kushal, Ayaan.

Aegis Vault grows our micro-project (a single-file AES-256-GCM tool) into a full application: a CLI plus a local web UI that encrypts files securely, shows *how* AES works, and teaches users why their password choices matter.

## What is it for?
- Protect files (PDFs, text, images, archives) with strong, authenticated encryption.
- Make encryption understandable: see rounds, bit diffusion and password strength.
- Everything runs on your machine. No cloud, no accounts, no telemetry.

## How it works (short version)
1. You pick a file and a password.
2. A random salt and **Argon2id** turn the password into a 256-bit key (slow on purpose, memory-hard).
3. The file is split into chunks and each chunk is encrypted with **AES-256-GCM** using a unique nonce. GCM adds an authentication tag, so any tampering, truncation or reordering is detected.
4. The result is a single `.aegis` container: header (version, KDF params, salt, key slots) + encrypted chunks.
5. Decryption verifies every tag before releasing plaintext. A wrong password or a changed byte fails cleanly with no output file.

## Features
| Tool | What it does |
|---|---|
| **Vault** | Encrypt / decrypt files, streaming in chunks so large files use flat memory |
| **Inspector** | Reads an `.aegis` header without a password: version, KDF settings, slot count |
| **Password Lab** | Strength feedback and estimated brute-force cost |
| **Avalanche Lab** | Flip one input bit, see ~50% of output bits change |
| **Keys** | Key slots: several passwords can unlock the same file |
| **AES X-Ray** *(signature feature)* | Step through AES round by round: SubBytes, ShiftRows, MixColumns, AddRoundKey on a 4x4 state grid |

## Architecture
```
Browser UI (single-page, "Vault Glass")
        |  HTTP, localhost only, Host-header checked
Local server (Python)  <---->  CLI (`aegis`)
        |
Core engine: KDF -> container format -> chunked AES-GCM
        |
`cryptography` library (OpenSSL-backed AES)
```

## User workflow
Open app -> choose file -> set password (Password Lab feedback) -> Encrypt -> get `.aegis` -> later: Decrypt with password -> original restored and verified.

## Tech stack
Python 3.10+, `cryptography` (AES-GCM, Argon2id, requires a recent version), standard-library HTTP server, vanilla HTML/CSS/JS single page, pytest. See [TECHNICAL.md](TECHNICAL.md).

## Quick start
```bash
pip install -e .
aegis encrypt report.pdf        # -> report.pdf.aegis
aegis decrypt report.pdf.aegis  # -> report.pdf
aegis serve                     # opens the local web UI
```

## Docs
[PRD](PRD.md) | [TECHNICAL](TECHNICAL.md) | [DESIGN](DESIGN.md) | [AGENTS](AGENTS.md) | [SKILLS](SKILLS.md)

## Team
| Member | Focus |
|---|---|
| Amiya | Core engine, container format |
| Krrish | KDF, key slots, tests |
| Kushal | Web server and UI |
| Ayaan | AES X-Ray, docs, report/slides |

> Educational project. Not independently audited; do not rely on it as your only protection for critical data.
