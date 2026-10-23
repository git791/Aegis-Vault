"""
AES X-Ray: Educational AES-128 / AES-256 Round Visualizer.

=============================================================================
CRITICAL NOTICE: EDUCATIONAL IMPLEMENTATION ONLY.
DO NOT USE THIS MODULE FOR REAL DATA ENCRYPTION.
This code is written for pedagogical transparency, round inspection, and
test-vector verification against FIPS-197. Real-world file encryption in
Aegis Vault uses authenticated OpenSSL-backed AES-256-GCM via the
`cryptography` library in `aegis.engine`.
=============================================================================
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Standard Rijndael S-Box (FIPS-197 Section 5.1.1)
S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Round constants (Rcon)
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    """Multiplication by 0x02 in GF(2^8)."""
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1)


def bytes_to_matrix(data: bytes | List[int]) -> List[List[int]]:
    """Convert 16 bytes into a 4x4 column-major state matrix."""
    return [[data[r + 4 * c] for c in range(4)] for r in range(4)]


def matrix_to_bytes(state: List[List[int]]) -> bytes:
    """Convert a 4x4 column-major state matrix back to 16 bytes."""
    res = bytearray(16)
    for r in range(4):
        for c in range(4):
            res[r + 4 * c] = state[r][c]
    return bytes(res)


def matrix_to_hex_grid(state: List[List[int]]) -> List[List[str]]:
    """Format 4x4 matrix as 2-character uppercase hex strings."""
    return [[f"{state[r][c]:02X}" for c in range(4)] for r in range(4)]


def sub_bytes(state: List[List[int]]) -> List[List[int]]:
    """Non-linear byte substitution using the Rijndael S-Box."""
    return [[S_BOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state: List[List[int]]) -> List[List[int]]:
    """Cyclic byte shift of rows 1, 2, and 3."""
    new_state = [row[:] for row in state]
    new_state[0] = state[0]
    new_state[1] = [state[1][1], state[1][2], state[1][3], state[1][0]]
    new_state[2] = [state[2][2], state[2][3], state[2][0], state[2][1]]
    new_state[3] = [state[3][3], state[3][0], state[3][1], state[3][2]]
    return new_state


def mix_columns(state: List[List[int]]) -> List[List[int]]:
    """Linear column mixing over GF(2^8)."""
    new_state = [[0] * 4 for _ in range(4)]
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        new_state[0][c] = _xtime(s0) ^ (_xtime(s1) ^ s1) ^ s2 ^ s3
        new_state[1][c] = s0 ^ _xtime(s1) ^ (_xtime(s2) ^ s2) ^ s3
        new_state[2][c] = s0 ^ s1 ^ _xtime(s2) ^ (_xtime(s3) ^ s3)
        new_state[3][c] = (_xtime(s0) ^ s0) ^ s1 ^ s2 ^ _xtime(s3)
    return new_state


def add_round_key(state: List[List[int]], round_key_bytes: bytes) -> List[List[int]]:
    """XOR state matrix with the 16-byte round key."""
    key_matrix = bytes_to_matrix(round_key_bytes)
    return [[state[r][c] ^ key_matrix[r][c] for c in range(4)] for r in range(4)]


def sub_word(w: int) -> int:
    """Apply S-Box to each byte of a 32-bit word."""
    return (
        (S_BOX[(w >> 24) & 0xFF] << 24)
        | (S_BOX[(w >> 16) & 0xFF] << 16)
        | (S_BOX[(w >> 8) & 0xFF] << 8)
        | S_BOX[w & 0xFF]
    )


def rot_word(w: int) -> int:
    """Perform 1-byte left circular rotation on a 32-bit word."""
    return ((w << 8) & 0xFFFFFFFF) | (w >> 24)


def key_expansion(key: bytes) -> List[bytes]:
    """
    Rijndael key expansion for 128-bit (16B) or 256-bit (32B) keys.
    Returns list of 16-byte round keys (Nr + 1 round keys).
    """
    nk = len(key) // 4
    if nk not in (4, 8):
        raise ValueError(f"AES key must be 16 or 32 bytes (128 or 256 bits), got {len(key)}")

    nr = 10 if nk == 4 else 14
    total_words = 4 * (nr + 1)
    words = [0] * total_words

    for i in range(nk):
        words[i] = int.from_bytes(key[4 * i : 4 * i + 4], "big")

    for i in range(nk, total_words):
        temp = words[i - 1]
        if i % nk == 0:
            temp = sub_word(rot_word(temp)) ^ (RCON[i // nk] << 24)
        elif nk > 6 and (i % nk == 4):
            temp = sub_word(temp)
        words[i] = words[i - nk] ^ temp

    round_keys: List[bytes] = []
    for r in range(nr + 1):
        rk = b"".join(words[4 * r + c].to_bytes(4, "big") for c in range(4))
        round_keys.append(rk)

    return round_keys


def aes_encrypt_block(block: bytes, key: bytes) -> bytes:
    """Run AES block encryption and return ciphertext (16 bytes)."""
    trace = aes_xray_trace(block, key)
    return bytes.fromhex(trace["ciphertext_hex"])


def aes_xray_trace(block: bytes, key: bytes) -> Dict[str, Any]:
    """
    Step-by-step AES execution trace for educational visualization.
    Returns complete state after each transformation:
    - AddRoundKey 0
    - For each round 1..Nr-1: SubBytes, ShiftRows, MixColumns, AddRoundKey
    - Round Nr: SubBytes, ShiftRows, AddRoundKey
    """
    if len(block) != 16:
        raise ValueError(f"AES block must be 16 bytes, got {len(block)}")
    if len(key) not in (16, 32):
        raise ValueError(f"AES key must be 16 or 32 bytes, got {len(key)}")

    nr = 10 if len(key) == 16 else 14
    round_keys = key_expansion(key)

    steps: List[Dict[str, Any]] = []

    def record_step(
        rnd: int,
        name: str,
        title: str,
        description: str,
        state: List[List[int]],
        prev_state: Optional[List[List[int]]],
        rk: Optional[bytes] = None,
    ) -> None:
        state_hex_grid = matrix_to_hex_grid(state)
        changed_mask = [[False] * 4 for _ in range(4)]
        if prev_state is not None:
            for r in range(4):
                for c in range(4):
                    if state[r][c] != prev_state[r][c]:
                        changed_mask[r][c] = True

        steps.append({
            "round": rnd,
            "step_name": name,
            "title": title,
            "description": description,
            "state_hex_grid": state_hex_grid,
            "state_hex": matrix_to_bytes(state).hex(),
            "changed_mask": changed_mask,
            "round_key_hex": rk.hex() if rk else None,
        })

    # Initial state
    state = bytes_to_matrix(block)
    record_step(
        rnd=0,
        name="input",
        title="Input Plaintext State",
        description="Initial 16-byte plaintext loaded into the 4x4 state matrix in column-major order.",
        state=state,
        prev_state=None,
    )

    # Round 0: AddRoundKey
    prev = [row[:] for row in state]
    state = add_round_key(state, round_keys[0])
    record_step(
        rnd=0,
        name="add_round_key",
        title="Round 0: Initial AddRoundKey",
        description="Each byte of the state is combined with the corresponding byte of Round Key 0 using bitwise XOR.",
        state=state,
        prev_state=prev,
        rk=round_keys[0],
    )

    # Rounds 1 through Nr - 1
    for r in range(1, nr):
        # 1. SubBytes
        prev = [row[:] for row in state]
        state = sub_bytes(state)
        record_step(
            rnd=r,
            name="sub_bytes",
            title=f"Round {r}: SubBytes",
            description="Non-linear substitution: each byte is replaced using the Rijndael S-Box (multiplicative inverse in GF(2^8) followed by affine transform).",
            state=state,
            prev_state=prev,
        )

        # 2. ShiftRows
        prev = [row[:] for row in state]
        state = shift_rows(state)
        record_step(
            rnd=r,
            name="shift_rows",
            title=f"Round {r}: ShiftRows",
            description="Row 0 is unshifted, Row 1 shifts left by 1, Row 2 shifts left by 2, and Row 3 shifts left by 3, diffusing byte positions across rows.",
            state=state,
            prev_state=prev,
        )

        # 3. MixColumns
        prev = [row[:] for row in state]
        state = mix_columns(state)
        record_step(
            rnd=r,
            name="mix_columns",
            title=f"Round {r}: MixColumns",
            description="Each 4-byte column is multiplied by a fixed MDS polynomial matrix over GF(2^8), achieving maximum branch-number diffusion across columns.",
            state=state,
            prev_state=prev,
        )

        # 4. AddRoundKey
        prev = [row[:] for row in state]
        state = add_round_key(state, round_keys[r])
        record_step(
            rnd=r,
            name="add_round_key",
            title=f"Round {r}: AddRoundKey",
            description=f"State is XORed with Round Key {r} derived from the key schedule.",
            state=state,
            prev_state=prev,
            rk=round_keys[r],
        )

    # Final Round: Nr (SubBytes, ShiftRows, AddRoundKey - No MixColumns)
    prev = [row[:] for row in state]
    state = sub_bytes(state)
    record_step(
        rnd=nr,
        name="sub_bytes",
        title=f"Round {nr} (Final): SubBytes",
        description="Final round non-linear substitution using the S-Box.",
        state=state,
        prev_state=prev,
    )

    prev = [row[:] for row in state]
    state = shift_rows(state)
    record_step(
        rnd=nr,
        name="shift_rows",
        title=f"Round {nr} (Final): ShiftRows",
        description="Final round row shifts.",
        state=state,
        prev_state=prev,
    )

    prev = [row[:] for row in state]
    state = add_round_key(state, round_keys[nr])
    record_step(
        rnd=nr,
        name="add_round_key",
        title=f"Round {nr} (Final): AddRoundKey",
        description=f"Final round key addition with Round Key {nr}. MixColumns is omitted in the final round to make decryption symmetric.",
        state=state,
        prev_state=prev,
        rk=round_keys[nr],
    )

    final_ct = matrix_to_bytes(state)

    return {
        "disclaimer": "Educational implementation for visualization only. Not for real-world encryption.",
        "key_size_bits": len(key) * 8,
        "num_rounds": nr,
        "input_block_hex": block.hex(),
        "key_hex": key.hex(),
        "ciphertext_hex": final_ct.hex(),
        "steps": steps,
        "round_keys_hex": [rk.hex() for rk in round_keys],
    }
