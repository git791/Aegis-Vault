"""
Avalanche Lab: Demonstrates the Strict Avalanche Criterion (SAC) in AES.
Flipping a single input or key bit causes ~50% of ciphertext bits to change within 2-3 rounds.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from aegis.xray import aes_xray_trace


def count_set_bits(n: int) -> int:
    """Return count of set bits in integer."""
    return bin(n).count("1")


def hamming_distance(b1: bytes, b2: bytes) -> int:
    """Calculate bit-level Hamming distance between two byte sequences."""
    return sum(count_set_bits(x ^ y) for x, y in zip(b1, b2))


def flip_bit(data: bytes, bit_index: int) -> bytes:
    """Flip the specified bit (0-indexed) in a byte string."""
    if bit_index < 0 or bit_index >= len(data) * 8:
        raise ValueError(f"Bit index {bit_index} out of range for {len(data)} bytes")

    byte_idx = bit_index // 8
    bit_in_byte = bit_index % 8

    arr = bytearray(data)
    arr[byte_idx] ^= (1 << (7 - bit_in_byte))
    return bytes(arr)


def run_avalanche_experiment(
    plaintext: bytes,
    key: bytes,
    flip_target: str = "plaintext",  # 'plaintext' or 'key'
    bit_index: int = 0,
) -> Dict[str, Any]:
    """
    Execute avalanche comparison between original and 1-bit flipped inputs.
    Returns round-by-round Hamming distance, bit percentages, and state grids.
    """
    if len(plaintext) != 16:
        raise ValueError("Plaintext must be exactly 16 bytes for AES block avalanche")
    if len(key) not in (16, 32):
        raise ValueError("Key must be 16 or 32 bytes")

    if flip_target == "plaintext":
        pt_orig = plaintext
        pt_mod = flip_bit(plaintext, bit_index)
        key_orig = key
        key_mod = key
    elif flip_target == "key":
        pt_orig = plaintext
        pt_mod = plaintext
        key_orig = key
        key_mod = flip_bit(key, bit_index)
    else:
        raise ValueError(f"Unknown flip_target: {flip_target}")

    trace1 = aes_xray_trace(pt_orig, key_orig)
    trace2 = aes_xray_trace(pt_mod, key_mod)

    # Group step outputs by round end
    rounds1: Dict[int, bytes] = {}
    rounds2: Dict[int, bytes] = {}

    for s in trace1["steps"]:
        if s["step_name"] in ("input", "add_round_key"):
            rounds1[s["round"]] = bytes.fromhex(s["state_hex"])

    for s in trace2["steps"]:
        if s["step_name"] in ("input", "add_round_key"):
            rounds2[s["round"]] = bytes.fromhex(s["state_hex"])

    round_stats: List[Dict[str, Any]] = []
    total_rounds = trace1["num_rounds"]

    for r in range(total_rounds + 1):
        b1 = rounds1.get(r, b"")
        b2 = rounds2.get(r, b"")
        if not b1 or not b2:
            continue

        h_dist = hamming_distance(b1, b2)
        pct = round((h_dist / 128.0) * 100.0, 2)
        diff_bytes = [i for i, (x, y) in enumerate(zip(b1, b2)) if x != y]

        round_stats.append({
            "round": r,
            "round_name": "Initial" if r == 0 else f"Round {r}",
            "hamming_distance_bits": h_dist,
            "diffusion_percentage": pct,
            "differing_bytes_count": len(diff_bytes),
            "state_original_hex": b1.hex(),
            "state_flipped_hex": b2.hex(),
        })

    final_h_dist = hamming_distance(
        bytes.fromhex(trace1["ciphertext_hex"]),
        bytes.fromhex(trace2["ciphertext_hex"]),
    )
    final_pct = round((final_h_dist / 128.0) * 100.0, 2)

    return {
        "flip_target": flip_target,
        "bit_index": bit_index,
        "original_plaintext_hex": pt_orig.hex(),
        "flipped_plaintext_hex": pt_mod.hex(),
        "original_key_hex": key_orig.hex(),
        "flipped_key_hex": key_mod.hex(),
        "final_hamming_distance_bits": final_h_dist,
        "final_diffusion_percentage": final_pct,
        "round_stats": round_stats,
        "sac_satisfied": 40.0 <= final_pct <= 60.0,  # ~50% expected
    }
