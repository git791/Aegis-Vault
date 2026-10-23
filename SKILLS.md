# SKILLS.md: Reusable workflows

Each skill is a repeatable procedure for contributors or AI agents.

## 1. add-feature
Write spec line in PRD -> implement -> add tests -> update README table -> update TECHNICAL if API/format changed.

## 2. change-container-format
Bump version byte -> keep a reader for the old version -> add migration test -> update TECHNICAL section 3.

## 3. tune-kdf
Benchmark Argon2id on target hardware -> pick parameters giving a noticeable delay (a fraction of a second) within memory limits -> store in header -> record numbers in TECHNICAL.

## 4. tamper-test
Encrypt sample -> flip one byte (header, chunk, tag) / truncate / swap chunks -> assert decrypt raises and no output file exists.

## 5. verify-xray
Run AES with FIPS-197 vectors -> assert ciphertext matches -> compare against `cryptography` output on random inputs.

## 6. ui-change
Use only DESIGN.md tokens -> check contrast with a tool -> test keyboard and reduced-motion -> screenshot at desktop and mobile widths.

## 7. release-check
`pytest` green -> `pip install -e .` in clean venv -> README quick start works verbatim -> docs match behaviour.
