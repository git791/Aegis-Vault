# AGENTS.md: Guide for AI coding agents working on Aegis Vault

## Project rules
1. **Never hand-roll cryptography for real use.** Real encryption goes through `cryptography` (AES-GCM, Argon2id). `xray.py` is educational only and must say so.
2. **Fail closed.** No plaintext output on auth failure; write to temp file, rename on success.
3. **Never reuse a nonce** under the same key.
4. **Never log or persist passwords, keys or plaintext.**
5. Server must stay bound to `127.0.0.1` with Host-header checks.
6. Do not claim security or accessibility numbers you have not measured.

## Commands
```bash
pip install -e .[dev]
pytest -q
aegis serve
```

## Layout
See README architecture and TECHNICAL section 4.

## Definition of done
Tests pass (incl. tamper/truncation/reorder), docs updated if format or API changed, container version bumped on format change, no new dependency without justification.

## Roles
| Agent | Scope |
|---|---|
| Engine agent | `kdf`, `container`, `engine`, tests |
| API/UI agent | `server`, `ui/index.html`, DESIGN.md compliance |
| Education agent | `xray`, Avalanche Lab, FIPS-197 vector tests |
| Docs agent | README, PRD, TECHNICAL, report/slides consistency |

## Style
Type hints, small functions, explicit exceptions from `errors.py`, comments explain *why*.
