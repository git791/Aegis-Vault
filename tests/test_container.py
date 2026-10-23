"""
Tests for Aegis container header parsing, serialization, and key slots.
"""

import io
import os
import struct
import pytest

from aegis.container import (
    DEFAULT_CHUNK_SIZE,
    MAGIC,
    ContainerHeader,
    KeySlot,
)
from aegis.errors import (
    AuthenticationError,
    CorruptContainerError,
    InvalidHeaderError,
    SlotError,
    UnsupportedVersionError,
)
from aegis.kdf import KDFParams

FAST_KDF = KDFParams(iterations=1, memory_cost=8192, lanes=1, key_len=32)


def test_header_round_trip():
    file_key = os.urandom(32)
    slot0 = KeySlot.create(0, "password123", file_key, label="primary", kdf_params=FAST_KDF)

    header = ContainerHeader(
        version=1,
        stream_id=os.urandom(16),
        nonce_prefix=os.urandom(8),
        chunk_size=DEFAULT_CHUNK_SIZE,
        slots=[slot0],
    )

    serialized = header.serialize()
    assert serialized.startswith(MAGIC)

    stream = io.BytesIO(serialized)
    parsed_header, bytes_read = ContainerHeader.read_from_stream(stream)

    assert bytes_read == len(serialized)
    assert parsed_header.version == 1
    assert parsed_header.stream_id == header.stream_id
    assert parsed_header.nonce_prefix == header.nonce_prefix
    assert parsed_header.chunk_size == header.chunk_size
    assert len(parsed_header.slots) == 1

    # Verify slot unwrap
    unwrapped = parsed_header.unlock_file_key("password123")
    assert unwrapped == file_key


def test_unlock_wrong_password():
    file_key = os.urandom(32)
    slot0 = KeySlot.create(0, "password123", file_key, kdf_params=FAST_KDF)
    header = ContainerHeader(
        version=1,
        stream_id=os.urandom(16),
        nonce_prefix=os.urandom(8),
        slots=[slot0],
    )
    with pytest.raises(AuthenticationError, match="Incorrect password"):
        header.unlock_file_key("WrongPassword")


def test_add_and_remove_slot():
    file_key = os.urandom(32)
    slot0 = KeySlot.create(0, "pwd1", file_key, label="primary", kdf_params=FAST_KDF)
    header = ContainerHeader(
        version=1,
        stream_id=os.urandom(16),
        nonce_prefix=os.urandom(8),
        slots=[slot0],
    )

    # Add slot 1
    new_slot = header.add_slot("pwd1", "pwd2", label="backup", kdf_params=FAST_KDF)
    assert len(header.slots) == 2
    assert new_slot.slot_id == 1

    # Both passwords can unlock master file key
    assert header.unlock_file_key("pwd1") == file_key
    assert header.unlock_file_key("pwd2") == file_key

    # Remove slot 0 using pwd2
    header.remove_slot(slot_id=0, password="pwd2")
    assert len(header.slots) == 1

    # pwd1 no longer unlocks
    with pytest.raises(AuthenticationError):
        header.unlock_file_key("pwd1")
    # pwd2 still unlocks
    assert header.unlock_file_key("pwd2") == file_key

    # Cannot remove the only remaining slot
    with pytest.raises(SlotError, match="last remaining"):
        header.remove_slot(slot_id=1, password="pwd2")


def test_invalid_magic():
    bad_bytes = b"WRONG\x01\x00\x00\x00\x10{}"
    with pytest.raises(CorruptContainerError, match="Invalid magic"):
        ContainerHeader.read_from_stream(io.BytesIO(bad_bytes))


def test_unsupported_version():
    bad_bytes = MAGIC + b"\x99\x00\x00\x00\x10{}"
    with pytest.raises(UnsupportedVersionError, match="Unsupported Aegis container version"):
        ContainerHeader.read_from_stream(io.BytesIO(bad_bytes))


def test_hostile_huge_header_length():
    # 2GB header length attempt
    huge_len_bytes = MAGIC + struct.pack(">BI", 1, 0x7FFFFFFF)
    with pytest.raises(InvalidHeaderError, match="safety limit"):
        ContainerHeader.read_from_stream(io.BytesIO(huge_len_bytes))


def test_truncated_header():
    # Header len claims 50 bytes, but stream has only 5
    truncated = MAGIC + struct.pack(">BI", 1, 50) + b'{"v":'
    with pytest.raises(CorruptContainerError, match="Truncated header"):
        ContainerHeader.read_from_stream(io.BytesIO(truncated))
