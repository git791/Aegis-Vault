"""
Tests for chunked streaming encryption and decryption engine.
"""

import io
import os
import pytest
from pathlib import Path

from aegis.engine import (
    decrypt_file,
    decrypt_stream,
    encrypt_file,
    encrypt_stream,
)
from aegis.kdf import KDFParams

FAST_KDF = KDFParams(iterations=1, memory_cost=8192, lanes=1, key_len=32)


def test_round_trip_text(tmp_path: Path):
    in_file = tmp_path / "hello.txt"
    in_file.write_text("Hello, Aegis Vault! World-class encryption.", encoding="utf-8")

    out_file = encrypt_file(in_file, password="testpassword123", kdf_params=FAST_KDF)
    assert out_file.exists()
    assert out_file.name == "hello.txt.aegis"

    dec_file = tmp_path / "hello_restored.txt"
    decrypt_file(out_file, output_path=dec_file, password="testpassword123")

    assert dec_file.exists()
    assert dec_file.read_text(encoding="utf-8") == in_file.read_text(encoding="utf-8")


def test_round_trip_binary(tmp_path: Path):
    # Simulated PDF / binary content with diverse bytes
    binary_data = bytes(range(256)) * 100  # 25,600 bytes
    in_file = tmp_path / "document.pdf"
    in_file.write_bytes(binary_data)

    out_file = encrypt_file(in_file, password="binary_password", kdf_params=FAST_KDF)
    dec_file = decrypt_file(out_file, password="binary_password")

    assert dec_file.read_bytes() == binary_data


def test_round_trip_empty_file(tmp_path: Path):
    empty_file = tmp_path / "empty.dat"
    empty_file.write_bytes(b"")

    out_file = encrypt_file(empty_file, password="empty_pwd", kdf_params=FAST_KDF)
    dec_file = decrypt_file(out_file, password="empty_pwd")

    assert dec_file.stat().st_size == 0
    assert dec_file.read_bytes() == b""


def test_round_trip_exact_chunk_boundary(tmp_path: Path):
    # Exactly one chunk (64 KiB)
    chunk_data = os.urandom(64 * 1024)
    chunk_file = tmp_path / "exact_chunk.bin"
    chunk_file.write_bytes(chunk_data)

    out_file = encrypt_file(chunk_file, password="chunk_password", kdf_params=FAST_KDF)
    dec_file = decrypt_file(out_file, password="chunk_password")

    assert dec_file.read_bytes() == chunk_data


def test_round_trip_multi_chunk(tmp_path: Path):
    # Multi-chunk file: 200 KiB across 4 chunks
    data = os.urandom(200 * 1024)
    multi_file = tmp_path / "multi.bin"
    multi_file.write_bytes(data)

    out_file = encrypt_file(multi_file, password="multi_password", kdf_params=FAST_KDF)
    dec_file = decrypt_file(out_file, password="multi_password")

    assert dec_file.read_bytes() == data


def test_same_file_encrypts_differently():
    # Semantic security: same plaintext + same password produces different ciphertexts
    pt = b"Deterministic plaintext to encrypt twice"
    pwd = "MySecretPassword"

    out1 = io.BytesIO()
    out2 = io.BytesIO()

    encrypt_stream(io.BytesIO(pt), out1, password=pwd, kdf_params=FAST_KDF)
    encrypt_stream(io.BytesIO(pt), out2, password=pwd, kdf_params=FAST_KDF)

    assert out1.getvalue() != out2.getvalue()


def test_progress_callback():
    data = os.urandom(150 * 1024)
    callbacks_called = []

    def cb(processed, total):
        callbacks_called.append((processed, total))

    in_s = io.BytesIO(data)
    out_s = io.BytesIO()
    encrypt_stream(in_s, out_s, password="pwd", kdf_params=FAST_KDF, progress_callback=cb, total_size=len(data))

    assert len(callbacks_called) > 0
    assert callbacks_called[-1][0] == len(data)
