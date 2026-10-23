# Product Requirements Document: Aegis Vault

## 1. Problem
Most people either skip encryption (too technical) or use opaque tools they cannot reason about. Students learning AES rarely see it work on real files.

## 2. Vision
A trustworthy, local, beautiful encryption tool that doubles as an interactive AES classroom.

## 3. Users
- **Everyday user:** wants to protect a PDF or folder archive with a password.
- **Student / evaluator:** wants to see and understand AES internals.
- **Developer:** wants a small, readable reference implementation using vetted primitives.

## 4. Goals
1. Encrypt/decrypt any file safely with authenticated encryption.
2. Make failure safe: wrong password or tampering never yields partial plaintext.
3. Teach AES visually (X-Ray, Avalanche Lab).
4. Work offline, install in one command.

## 5. Non-goals
Cloud sync, accounts, implementing our own cipher for real use, protecting against a compromised machine.

## 6. Functional requirements
| ID | Requirement | Priority |
|---|---|---|
| F1 | Encrypt/decrypt files via CLI and web UI | Must |
| F2 | Argon2id key derivation with random salt per file | Must |
| F3 | AES-256-GCM, unique nonce per chunk, chunked streaming | Must |
| F4 | Detect truncation, reordering, header and body tampering | Must |
| F5 | No output file written on failure | Must |
| F6 | Inspector reads header without password | Should |
| F7 | Key slots (multiple passwords per file) | Should |
| F8 | Password Lab strength feedback | Should |
| F9 | Avalanche Lab | Should |
| F10 | **AES X-Ray** round-by-round visualizer (educational, clearly labelled not for real encryption) | Should (wow feature) |

## 7. Non-functional requirements
- Memory stays flat regardless of file size (streaming).
- Server binds to localhost only and rejects unexpected Host headers.
- Accessible UI: keyboard navigable, readable contrast, reduced-motion support.
- Test suite covers round-trip, wrong key, tamper, truncation, reordering, hostile headers.

## 8. Success metrics
- Round-trip hash equality on text, PDF and large files.
- 100% of tamper tests rejected.
- A new user encrypts a file in under 1 minute.

## 9. Milestones
1. Engine + tests. 2. CLI. 3. Web server + UI. 4. X-Ray feature. 5. Docs, report, demo.

## 10. Risks
Misuse as sole protection of critical data (mitigated by disclaimer); forgotten password means unrecoverable data (stated clearly in UI).
