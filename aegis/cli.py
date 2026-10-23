"""
Command-line interface for Aegis Vault (`aegis`).
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Optional

from aegis.avalanche import run_avalanche_experiment
from aegis.container import ContainerHeader
from aegis.engine import decrypt_file, encrypt_file
from aegis.errors import AegisError
from aegis.slots import add_key_slot, inspect_file, remove_key_slot
from aegis.strength import analyze_password
from aegis.xray import aes_xray_trace


def _prompt_password(prompt: str = "Enter password: ", confirm: bool = False) -> str:
    """Prompt user securely for password from terminal."""
    pwd = getpass.getpass(prompt)
    if not pwd:
        print("Error: Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if confirm:
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            print("Error: Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return pwd


def cmd_encrypt(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File '{path}' not found.", file=sys.stderr)
        return 1

    password = args.password
    if not password:
        password = _prompt_password("Enter vault encryption password: ", confirm=True)

    print(f"Encrypting '{path}'...")
    try:
        out_path = encrypt_file(path, output_path=args.output, password=password)
        print(f"Success: Encrypted container saved to '{out_path}'.")
        return 0
    except Exception as e:
        print(f"Encryption failed: {e}", file=sys.stderr)
        return 1


def cmd_decrypt(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: Container file '{path}' not found.", file=sys.stderr)
        return 1

    password = args.password
    if not password:
        password = _prompt_password("Enter vault decryption password: ")

    print(f"Decrypting and authenticating '{path}'...")
    try:
        out_path = decrypt_file(path, output_path=args.output, password=password)
        print(f"Success: File verified and restored to '{out_path}'.")
        return 0
    except AegisError as e:
        print(f"Decryption failed: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


def cmd_inspect(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File '{path}' not found.", file=sys.stderr)
        return 1

    try:
        meta = inspect_file(path)
        if args.json:
            print(json.dumps(meta, indent=2))
        else:
            print("=== Aegis Container Header ===")
            print(f"File Name:       {meta['file_name']}")
            print(f"File Size:       {meta['file_size']} bytes")
            print(f"Version:         {meta['version']}")
            print(f"Chunk Size:      {meta['chunk_size']} bytes")
            print(f"Header Size:     {meta['header_length_bytes']} bytes")
            print(f"Payload Size:    {meta['payload_length_bytes']} bytes (~{meta['approx_chunks']} chunks)")
            print(f"Stream ID:       {meta['stream_id']}")
            print(f"Nonce Prefix:    {meta['nonce_prefix']}")
            print(f"Created At:      {meta['created_at']}")
            print(f"\nKey Slots ({meta['slot_count']}):")
            for s in meta["slots"]:
                kdf = s["kdf"]
                print(f"  Slot {s['slot_id']} [{s['label']}]:")
                print(f"    KDF:         {kdf['algorithm']} (iterations={kdf['iterations']}, memory={kdf['memory_cost']}KiB, lanes={kdf['lanes']})")
                print(f"    Salt:        {s['salt_hex']}")
                print(f"    Nonce:       {s['nonce_hex']}")
                print(f"    Wrapped Key: {s['wrapped_key_len']} bytes (AES-256-GCM wrapped)")
        return 0
    except Exception as e:
        print(f"Inspection failed: {e}", file=sys.stderr)
        return 1


def cmd_slot(args: argparse.Namespace) -> int:
    sub = args.slot_cmd
    path = Path(args.file)
    if not path.is_file():
        print(f"Error: File '{path}' not found.", file=sys.stderr)
        return 1

    if sub == "list":
        return cmd_inspect(args)

    if sub == "add":
        curr_pwd = args.current_password
        if not curr_pwd:
            curr_pwd = _prompt_password("Enter current container password: ")
        new_pwd = args.new_password
        if not new_pwd:
            new_pwd = _prompt_password("Enter new slot password: ", confirm=True)

        try:
            slot_id = add_key_slot(
                container_path=path,
                current_password=curr_pwd,
                new_password=new_pwd,
                label=args.label or f"slot_{path.stem}",
            )
            print(f"Success: Added key slot {slot_id} to '{path}'.")
            return 0
        except Exception as e:
            print(f"Failed to add key slot: {e}", file=sys.stderr)
            return 1

    if sub == "remove":
        if args.slot_id is None:
            print("Error: --slot-id is required for slot removal.", file=sys.stderr)
            return 1
        pwd = args.password
        if not pwd:
            pwd = _prompt_password("Enter valid password to verify slot removal: ")

        try:
            remove_key_slot(container_path=path, slot_id=args.slot_id, password=pwd)
            print(f"Success: Key slot {args.slot_id} removed from '{path}'.")
            return 0
        except Exception as e:
            print(f"Failed to remove key slot: {e}", file=sys.stderr)
            return 1

    return 0


def cmd_strength(args: argparse.Namespace) -> int:
    pwd = args.password
    if not pwd:
        pwd = getpass.getpass("Enter password to evaluate: ")
    res = analyze_password(pwd)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print("=== Password Lab Analysis ===")
        print(f"Length:     {res['password_length']} characters")
        print(f"Entropy:    {res['entropy_bits']} bits")
        print(f"Score:      {res['score']} / 4 ({res['label']})")
        print(f"Composition: lower={res['has_lowercase']}, upper={res['has_uppercase']}, digits={res['has_digits']}, symbols={res['has_symbols']}")
        print("\nEstimated Brute-force Times:")
        print(f"  Online Throttled:       {res['estimates']['online_throttled']['time']}")
        print(f"  GPU Cluster (PBKDF2):   {res['estimates']['gpu_fast_hash']['time']}")
        print(f"  Argon2id (Aegis Vault): {res['estimates']['argon2id_vault']['time']}")
        print(f"  Defense: {res['estimates']['argon2id_vault']['advantage']}")
        if res["suggestions"]:
            print("\nSuggestions:")
            for s in res["suggestions"]:
                print(f"  - {s}")
    return 0


def cmd_avalanche(args: argparse.Namespace) -> int:
    pt = bytes.fromhex(args.plaintext_hex) if args.plaintext_hex else b"0123456789abcdef"
    k = bytes.fromhex(args.key_hex) if args.key_hex else b"sixteenbytekey16"
    res = run_avalanche_experiment(
        plaintext=pt,
        key=k,
        flip_target=args.target,
        bit_index=args.bit,
    )
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"=== AES Avalanche Experiment (Flipped bit {args.bit} in {args.target}) ===")
        for r in res["round_stats"]:
            print(f"  {r['round_name']:<10}: {r['hamming_distance_bits']:>3}/128 bits ({r['diffusion_percentage']:>5}%) diff [{r['differing_bytes_count']:>2}/16 bytes]")
        print(f"\nFinal Diffusion: {res['final_diffusion_percentage']}% (Strict Avalanche Criterion Satisfied: {res['sac_satisfied']})")
    return 0


def cmd_xray(args: argparse.Namespace) -> int:
    block = bytes.fromhex(args.block_hex) if args.block_hex else bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    key = bytes.fromhex(args.key_hex) if args.key_hex else bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    trace = aes_xray_trace(block, key)
    if args.json:
        print(json.dumps(trace, indent=2))
    else:
        print("=== AES X-Ray (Educational Step-by-Step Tracer) ===")
        print(f"Notice: {trace['disclaimer']}")
        print(f"Key Size: {trace['key_size_bits']} bits | Rounds: {trace['num_rounds']}")
        print(f"Plaintext:  {trace['input_block_hex']}")
        print(f"Ciphertext: {trace['ciphertext_hex']}\n")
        for s in trace["steps"]:
            if args.round is not None and s["round"] != args.round:
                continue
            print(f"[{s['round']}] {s['title']}")
            for row in s["state_hex_grid"]:
                print("  " + " ".join(row))
            print()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from aegis.server import run_server
    return run_server(host=args.host, port=args.port)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis Vault: Local-first file encryption and AES teaching lab",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # encrypt
    p_enc = sub.add_parser("encrypt", help="Encrypt a file into an .aegis container")
    p_enc.add_argument("file", help="Input file to encrypt")
    p_enc.add_argument("-o", "--output", help="Output .aegis container path")
    p_enc.add_argument("-p", "--password", help="Encryption password (or prompted)")
    p_enc.set_defaults(func=cmd_encrypt)

    # decrypt
    p_dec = sub.add_parser("decrypt", help="Decrypt and verify an .aegis container")
    p_dec.add_argument("file", help="Input .aegis container to decrypt")
    p_dec.add_argument("-o", "--output", help="Output plaintext file path")
    p_dec.add_argument("-p", "--password", help="Decryption password (or prompted)")
    p_dec.set_defaults(func=cmd_decrypt)

    # inspect
    p_insp = sub.add_parser("inspect", help="Read container header without password")
    p_insp.add_argument("file", help="Container file to inspect")
    p_insp.add_argument("--json", action="store_true", help="Output raw JSON")
    p_insp.set_defaults(func=cmd_inspect)

    # slot
    p_slot = sub.add_parser("slot", help="Manage multi-password key slots")
    p_slot_sub = p_slot.add_subparsers(dest="slot_cmd", required=True)

    p_s_list = p_slot_sub.add_parser("list", help="List key slots in container")
    p_s_list.add_argument("file", help="Container file")
    p_s_list.add_argument("--json", action="store_true", help="Output JSON")

    p_s_add = p_slot_sub.add_parser("add", help="Add a new password slot")
    p_s_add.add_argument("file", help="Container file")
    p_s_add.add_argument("-p", "--current-password", help="Current password")
    p_s_add.add_argument("--new-password", help="New slot password")
    p_s_add.add_argument("--label", help="Optional slot label")

    p_s_rem = p_slot_sub.add_parser("remove", help="Remove a password slot")
    p_s_rem.add_argument("file", help="Container file")
    p_s_rem.add_argument("--slot-id", type=int, required=True, help="Slot ID to remove")
    p_s_rem.add_argument("-p", "--password", help="Verification password")
    p_slot.set_defaults(func=cmd_slot)

    # strength
    p_str = sub.add_parser("strength", help="Analyze password strength and crack time")
    p_str.add_argument("password", nargs="?", help="Password to evaluate")
    p_str.add_argument("--json", action="store_true", help="Output JSON")
    p_str.set_defaults(func=cmd_strength)

    # avalanche
    p_ava = sub.add_parser("avalanche", help="Run AES bit-diffusion avalanche experiment")
    p_ava.add_argument("--plaintext-hex", help="16-byte plaintext in hex")
    p_ava.add_argument("--key-hex", help="16/32-byte key in hex")
    p_ava.add_argument("--bit", type=int, default=0, help="Bit index to flip (0-127)")
    p_ava.add_argument("--target", choices=["plaintext", "key"], default="plaintext", help="Flip in plaintext or key")
    p_ava.add_argument("--json", action="store_true", help="Output JSON")
    p_ava.set_defaults(func=cmd_avalanche)

    # xray
    p_xray = sub.add_parser("xray", help="Run step-by-step AES round tracer")
    p_xray.add_argument("--block-hex", help="16-byte block in hex")
    p_xray.add_argument("--key-hex", help="16/32-byte key in hex")
    p_xray.add_argument("--round", type=int, help="Filter to specific round number")
    p_xray.add_argument("--json", action="store_true", help="Output JSON")
    p_xray.set_defaults(func=cmd_xray)

    # serve
    p_srv = sub.add_parser("serve", help="Start web server and Vault Glass UI")
    p_srv.add_argument("--host", default=None, help="Host interface (default: 127.0.0.1 for local, 0.0.0.0 for cloud)")
    p_srv.add_argument("--port", type=int, default=None, help="Server port (default: 8000 or $PORT env var)")
    p_srv.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
