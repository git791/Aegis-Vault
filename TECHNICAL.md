# Technical Document

## 1. Stack and rationale
| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.10+ | Readable, strong crypto bindings, easy to demo |
| Crypto | `cryptography` (OpenSSL) | Vetted AES-GCM and Argon2id; we never hand-roll real encryption |
| KDF | Argon2id (RFC 9106) | Memory-hard, recommended for password hashing; replaces our earlier PBKDF2 |
| Cipher | AES-256-GCM | Confidentiality + integrity in one primitive |
| Server | Python stdlib HTTP, localhost | No dependency surface; simple |
| UI | Vanilla HTML/CSS/JS single file | No build step, easy to audit |
| Tests | pytest | Standard |

Verify exact KDF parameters and the minimum `cryptography` version against current docs before release; Argon2id support was added in recent releases.

## 2. Crypto design
- **Key derivation:** `key = Argon2id(password, salt[16 random bytes], t, m, p) -> 32 bytes`. Parameters are stored in the header so they can be raised later. Start from OWASP/RFC 9106 guidance and tune so one derivation takes a noticeable fraction of a second on target hardware.
- **Key slots:** a random 256-bit *file key* encrypts the data. Each slot stores that file key wrapped (AES-GCM) under a password-derived key, so adding or removing a password does not re-encrypt the file.
- **Chunked encryption:** plaintext is split into fixed-size chunks (e.g. 64 KiB). Each chunk is AES-GCM encrypted with nonce = per-file random prefix + 32/64-bit counter, so nonces never repeat under one key.
- **Anti-truncation / reordering:** the chunk index and a final-chunk flag are bound into the AAD (additional authenticated data), together with the header hash. Removing, swapping or appending chunks fails authentication.
- **Failure behaviour:** decrypt to a temp file, verify every tag, rename only on success.

## 3. Container format (`.aegis`)
```
magic "AEGIS" | version (1B) | header_len (4B) | header (KDF params, salt,
nonce prefix, chunk size, slots[]) | chunk_0 | chunk_1 | ... | chunk_n(final flag)
chunk_i = ciphertext || 16-byte GCM tag
```
Header length is capped when parsing so hostile files cannot cause huge allocations.

## 4. Modules
```
aegis/
  errors.py      typed exceptions
  kdf.py         Argon2id wrapper
  container.py   header read/write, slots
  engine.py      streaming encrypt/decrypt
  cli.py         `aegis` command
  server.py      local API + static UI
  xray.py        educational AES (test-vector verified), NOT for real use
  ui/index.html  Vault Glass single page
tests/
```

## 5. Local API
`POST /api/encrypt`, `POST /api/decrypt`, `POST /api/inspect`, `POST /api/strength`, `POST /api/xray`, `POST /api/avalanche`. Bound to `127.0.0.1`; Host header allow-list; no CORS wildcard.

## 6. AES X-Ray design
A from-scratch AES-128/256 round implementation used only for visualization. It is checked against the official FIPS-197 test vectors. The API returns the state after each step of each round; the UI renders the 4x4 byte grid and highlights changed bytes.

## 7. Testing
Round trip (text, PDF, empty, exact-chunk-size, large), wrong password, bit-flip in header/body, truncation, chunk reordering, hostile header lengths, same input encrypted twice differs, memory flat on large files, FIPS-197 vectors for X-Ray.

## 8. Known limits
Not audited; a compromised host can read keys from memory; forgotten passwords are unrecoverable.
