"""
Tamper resistance and integrity verification tests for Aegis Vault.
Asserts that any bit-flip, truncation, reordering, or wrong password
fails cleanly and NEVER produces an output file on disk.
"""

import io
import os
import struct
import pytest
from pathlib import Path

from aegis.container import ContainerHeader, MAGIC
from aegis.engine import decrypt_file, encrypt_file
from aegis.errors import AuthenticationError, CorruptContainerError, TamperError
from aegis.kdf import KDFParams

FAST_KDF = KDFParams(iterations=1, memory_cost=8192, lanes=1, key_len=32)


@pytest.fixture
def encrypted_sample(tmp_path: Path):
    """Create a 3-chunk encrypted test container."""
    data = b"CHUNK_ZERO_DATA" * 5000 + b"CHUNK_ONE_DATA" * 5000 + b"CHUNK_TWO_DATA" * 5000
    pt_file = tmp_path / "original.dat"
    pt_file.write_bytes(data)

    ct_file = encrypt_file(
        pt_file,
        password="ValidPassword123",
        chunk_size=16 * 1024,  # 16KB chunks to easily create multi-chunk container
        kdf_params=FAST_KDF,
    )
    return ct_file, data


def test_wrong_password_fails_closed(tmp_path: Path, encrypted_sample):
    ct_file, _ = encrypted_sample
    out_file = tmp_path / "should_not_exist.dat"

    with pytest.raises(AuthenticationError):
        decrypt_file(ct_file, output_path=out_file, password="WrongPassword!")

    # Verify fail-closed: output file must NOT exist on disk
    assert not out_file.exists()


def test_tamper_header_stream_id(tmp_path: Path, encrypted_sample):
    ct_file, _ = encrypted_sample
    content = bytearray(ct_file.read_bytes())

    # Locate stream_id in the header JSON and flip a hex byte
    idx = content.find(b"stream_id") + 12
    content[idx] ^= 0x01

    tampered_file = tmp_path / "tampered_header.aegis"
    tampered_file.write_bytes(content)

    out_file = tmp_path / "out_header.dat"
    with pytest.raises((TamperError, AuthenticationError, CorruptContainerError)):
        decrypt_file(tampered_file, output_path=out_file, password="ValidPassword123")

    assert not out_file.exists()


def test_tamper_header_version_byte(tmp_path: Path, encrypted_sample):
    ct_file, _ = encrypted_sample
    content = bytearray(ct_file.read_bytes())

    # Flip the container binary version byte (index 5)
    content[5] = 0x99

    tampered_file = tmp_path / "tampered_version.aegis"
    tampered_file.write_bytes(content)

    out_file = tmp_path / "out_ver.dat"
    with pytest.raises(CorruptContainerError):
        decrypt_file(tampered_file, output_path=out_file, password="ValidPassword123")

    assert not out_file.exists()


def test_tamper_chunk_ciphertext_byte(tmp_path: Path, encrypted_sample):
    ct_file, _ = encrypted_sample
    content = bytearray(ct_file.read_bytes())

    # Flip a byte near the middle of payload
    tamper_offset = len(content) - 1000
    content[tamper_offset] ^= 0xFF

    tampered_file = tmp_path / "tampered_chunk.aegis"
    tampered_file.write_bytes(content)

    out_file = tmp_path / "out_chunk.dat"
    with pytest.raises(TamperError, match="Authentication failed on chunk"):
        decrypt_file(tampered_file, output_path=out_file, password="ValidPassword123")

    assert not out_file.exists()


def test_tamper_gcm_auth_tag(tmp_path: Path, encrypted_sample):
    ct_file, _ = encrypted_sample
    content = bytearray(ct_file.read_bytes())

    # Flip a byte in the final 16-byte GCM tag
    content[-5] ^= 0x42

    tampered_file = tmp_path / "tampered_tag.aegis"
    tampered_file.write_bytes(content)

    out_file = tmp_path / "out_tag.dat"
    with pytest.raises(TamperError, match="Authentication failed on chunk"):
        decrypt_file(tampered_file, output_path=out_file, password="ValidPassword123")

    assert not out_file.exists()


def test_tamper_truncation(tmp_path: Path, encrypted_sample):
    ct_file, _ = encrypted_sample
    content = ct_file.read_bytes()

    # Truncate container by cutting off the last 100 bytes (removing final tag/part of chunk)
    truncated_content = content[:-100]

    tampered_file = tmp_path / "truncated.aegis"
    tampered_file.write_bytes(truncated_content)

    out_file = tmp_path / "out_truncated.dat"
    with pytest.raises(TamperError):
        decrypt_file(tampered_file, output_path=out_file, password="ValidPassword123")

    assert not out_file.exists()


def test_tamper_truncate_final_chunk(tmp_path: Path):
    """Truncate the entire final chunk so previous chunk ends at EOF."""
    data = os.urandom(32 * 1024)  # 2 chunks with 16KB chunk size
    pt_file = tmp_path / "orig.dat"
    pt_file.write_bytes(data)

    ct_file = encrypt_file(
        pt_file,
        password="pwd",
        chunk_size=16 * 1024,
        kdf_params=FAST_KDF,
    )
    raw = ct_file.read_bytes()

    # Read header len
    prefix = raw[:10]
    ver, hlen = struct.unpack(">BI", prefix[5:10])
    header_end = 10 + hlen
    chunk0_len = 16 * 1024 + 16

    # Cut off chunk 1 entirely
    cut_file = tmp_path / "missing_chunk1.aegis"
    cut_file.write_bytes(raw[:header_end + chunk0_len])

    out_file = tmp_path / "out_cut.dat"
    # Chunk 0 was encrypted with is_final=0, but at EOF decryptor checks is_final=1 -> AAD mismatch
    with pytest.raises(TamperError, match="Authentication failed on chunk"):
        decrypt_file(cut_file, output_path=out_file, password="pwd")

    assert not out_file.exists()


def test_tamper_append_trailing_garbage(tmp_path: Path, encrypted_sample):
    ct_file, _ = encrypted_sample
    content = ct_file.read_bytes() + b"TRAILING_UNAUTHENTICATED_BYTES"

    tampered_file = tmp_path / "appended.aegis"
    tampered_file.write_bytes(content)

    out_file = tmp_path / "out_appended.dat"
    with pytest.raises(TamperError):
        decrypt_file(tampered_file, output_path=out_file, password="ValidPassword123")

    assert not out_file.exists()
