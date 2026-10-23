"""
Tests for Password Lab and Avalanche Lab.
"""

from aegis.avalanche import flip_bit, hamming_distance, run_avalanche_experiment
from aegis.strength import analyze_password, calculate_entropy


def test_entropy_calculation():
    assert calculate_entropy("") == 0.0
    # Lowercase only: 8 * log2(26) ~ 37.6
    ent_low = calculate_entropy("abcdefgh")
    assert 35.0 <= ent_low <= 40.0

    # Complex password
    ent_complex = calculate_entropy("C0mpl3x!P@ssw0rd#2026")
    assert ent_complex > 100.0


def test_password_strength_scores():
    # Very weak
    r0 = analyze_password("12345")
    assert r0["score"] == 0

    # Weak dictionary
    r1 = analyze_password("password123")
    assert r1["score"] <= 2
    assert r1["patterns_detected"] is True

    # Strong
    r_strong = analyze_password("Xkcd-Battery-9876!@#$Staple")
    assert r_strong["score"] >= 3
    assert "argon2id_vault" in r_strong["estimates"]


def test_flip_bit():
    data = b"\x00\x00"
    # Flip bit 0 (most significant bit of byte 0)
    flipped = flip_bit(data, 0)
    assert flipped == b"\x80\x00"

    # Flip bit 15 (least significant bit of byte 1)
    flipped15 = flip_bit(data, 15)
    assert flipped15 == b"\x00\x01"


def test_hamming_distance():
    b1 = b"\x00\xFF"
    b2 = b"\xFF\xFF"
    assert hamming_distance(b1, b2) == 8


def test_avalanche_strict_criterion():
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    # Flip bit 0 in plaintext
    exp = run_avalanche_experiment(pt, key, flip_target="plaintext", bit_index=0)

    stats = exp["round_stats"]
    assert len(stats) == 11  # Initial + 10 rounds for AES-128
    assert stats[0]["hamming_distance_bits"] == 1  # only 1 bit flipped initially

    # By Round 3+, bits should diffuse significantly
    r3 = stats[3]
    assert r3["diffusion_percentage"] > 35.0

    # Strict Avalanche Criterion in final round (~40-60%)
    assert exp["sac_satisfied"] is True
