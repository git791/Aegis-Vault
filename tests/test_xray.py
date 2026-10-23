"""
Tests for educational AES X-Ray round tracer and FIPS-197 test vector compliance.
"""

import os
import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from aegis.xray import (
    aes_encrypt_block,
    aes_xray_trace,
    key_expansion,
)


def test_fips_197_aes_128_appendix_b():
    # Official FIPS 197 Appendix B Test Vector
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_ct = "3925841d02dc09fbdc118597196a0b32"

    ct = aes_encrypt_block(pt, key)
    assert ct.hex() == expected_ct


def test_fips_197_aes_256_appendix_c3():
    # Official FIPS 197 Appendix C.3 Test Vector
    key = bytes(range(32))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = "8ea2b7ca516745bfeafc49904b496089"

    ct = aes_encrypt_block(pt, key)
    assert ct.hex() == expected_ct


def test_nist_sp800_38a_aes_256():
    # Official NIST SP 800-38A Section F.1.5 Test Vector
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    expected_ct = "f3eed1bdb5d2a03c064b5a7e3db181f8"

    ct = aes_encrypt_block(pt, key)
    assert ct.hex() == expected_ct


def test_xray_matches_openssl_random_blocks():
    # Verify our Rijndael implementation against OpenSSL on random blocks
    for _ in range(5):
        key128 = os.urandom(16)
        block = os.urandom(16)

        # OpenSSL result
        c = Cipher(algorithms.AES(key128), modes.ECB()).encryptor()
        openssl_ct = c.update(block) + c.finalize()

        xray_ct = aes_encrypt_block(block, key128)
        assert xray_ct == openssl_ct

        # 256-bit test
        key256 = os.urandom(32)
        c2 = Cipher(algorithms.AES(key256), modes.ECB()).encryptor()
        openssl_ct2 = c2.update(block) + c2.finalize()

        xray_ct2 = aes_encrypt_block(block, key256)
        assert xray_ct2 == openssl_ct2


def test_xray_trace_structure():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    block = bytes.fromhex("3243f6a8885a308d313198a2e0370734")

    trace = aes_xray_trace(block, key)
    assert "disclaimer" in trace
    assert trace["num_rounds"] == 10
    assert trace["key_size_bits"] == 128
    assert len(trace["round_keys_hex"]) == 11

    # Check step sequence
    steps = trace["steps"]
    assert steps[0]["step_name"] == "input"
    assert steps[1]["step_name"] == "add_round_key"
    assert steps[-1]["step_name"] == "add_round_key"

    # Verify 4x4 matrix dimensions
    for s in steps:
        grid = s["state_hex_grid"]
        assert len(grid) == 4
        assert all(len(row) == 4 for row in grid)
        mask = s["changed_mask"]
        assert len(mask) == 4
        assert all(len(row) == 4 for row in mask)
