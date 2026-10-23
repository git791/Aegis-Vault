"""
Core streaming encryption and decryption engine for Aegis Vault.
Uses AES-256-GCM with unique chunk nonces and anti-tamper AAD binding.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import BinaryIO, Callable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis.container import (
    DEFAULT_CHUNK_SIZE,
    ContainerHeader,
    KeySlot,
)
from aegis.errors import (
    AegisError,
    AuthenticationError,
    CorruptContainerError,
    TamperError,
)
from aegis.kdf import KDFParams

ProgressCallback = Callable[[int, int], None]  # (bytes_processed, total_bytes)


def encrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    password: str | bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    kdf_params: Optional[KDFParams] = None,
    progress_callback: Optional[ProgressCallback] = None,
    total_size: int = 0,
) -> ContainerHeader:
    """
    Stream-encrypt data from in_stream to out_stream using AES-256-GCM.
    Writes full Aegis container header followed by authenticated chunks.
    """
    if not password:
        raise ValueError("Password cannot be empty")

    file_key = os.urandom(32)  # Master 256-bit file key
    nonce_prefix = os.urandom(8)  # 8 bytes per-file random nonce prefix
    stream_id = os.urandom(16)  # 16 bytes unique stream identifier

    slot0 = KeySlot.create(
        slot_id=0,
        password=password,
        file_key=file_key,
        label="primary",
        kdf_params=kdf_params,
    )

    header = ContainerHeader(
        version=1,
        stream_id=stream_id,
        nonce_prefix=nonce_prefix,
        chunk_size=chunk_size,
        slots=[slot0],
    )

    out_stream.write(header.serialize())
    stream_binding = header.compute_stream_binding()
    aesgcm = AESGCM(file_key)

    bytes_read_total = 0
    chunk_index = 0
    current_chunk = in_stream.read(chunk_size)

    while True:
        next_chunk = in_stream.read(chunk_size)
        is_final = len(next_chunk) == 0

        # 96-bit nonce: 8 bytes random prefix + 4 bytes chunk index
        nonce = nonce_prefix + struct.pack(">I", chunk_index)
        # Anti-truncation, anti-reordering AAD binding
        aad = stream_binding + struct.pack(">IB", chunk_index, 1 if is_final else 0)

        encrypted_chunk = aesgcm.encrypt(nonce, current_chunk, aad)
        out_stream.write(encrypted_chunk)

        bytes_read_total += len(current_chunk)
        if progress_callback:
            progress_callback(bytes_read_total, total_size)

        if is_final:
            break

        current_chunk = next_chunk
        chunk_index += 1

    return header


def decrypt_stream(
    in_stream: BinaryIO,
    out_stream: BinaryIO,
    password: str | bytes,
    progress_callback: Optional[ProgressCallback] = None,
    total_size: int = 0,
) -> ContainerHeader:
    """
    Stream-decrypt data from in_stream to out_stream.
    Verifies container header, unlocks file key via key slots,
    and validates every chunk's AES-GCM tag.
    Raises TamperError or AuthenticationError on any failure.
    """
    if not password:
        raise ValueError("Password cannot be empty")

    header, header_bytes_len = ContainerHeader.read_from_stream(in_stream)
    file_key = header.unlock_file_key(password)
    stream_binding = header.compute_stream_binding()
    aesgcm = AESGCM(file_key)

    chunk_size = header.chunk_size
    read_len = chunk_size + 16  # plaintext chunk + 16-byte GCM tag
    chunk_index = 0
    bytes_processed = header_bytes_len

    first_read = in_stream.read(read_len)
    if len(first_read) < 16:
        raise CorruptContainerError("Container has no encrypted payload or chunk is truncated")

    current_chunk_data = first_read

    while True:
        peek = in_stream.read(1)
        if len(peek) == 0:
            # EOF reached: current_chunk_data is the final chunk
            is_final = True
        else:
            is_final = False
            # Read remainder of next chunk so next loop iteration is ready
            next_remainder = in_stream.read(read_len - 1)
            next_chunk_data = peek + next_remainder

        if len(current_chunk_data) < 16:
            raise TamperError(f"Chunk {chunk_index} is shorter than 16-byte GCM tag (truncated)")

        if not is_final and len(current_chunk_data) != read_len:
            raise TamperError(
                f"Non-final chunk {chunk_index} length ({len(current_chunk_data)}) does not match expected {read_len}"
            )

        nonce = header.nonce_prefix + struct.pack(">I", chunk_index)
        aad = stream_binding + struct.pack(">IB", chunk_index, 1 if is_final else 0)

        try:
            plaintext = aesgcm.decrypt(nonce, current_chunk_data, aad)
        except InvalidTag as e:
            raise TamperError(
                f"Authentication failed on chunk {chunk_index}: data tampered, truncated, or reordered"
            ) from e

        out_stream.write(plaintext)
        bytes_processed += len(current_chunk_data)

        if progress_callback:
            progress_callback(bytes_processed, total_size)

        if is_final:
            break

        current_chunk_data = next_chunk_data
        chunk_index += 1

    return header


def encrypt_file(
    input_path: str | Path,
    output_path: Optional[str | Path] = None,
    password: str | bytes = "",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    kdf_params: Optional[KDFParams] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> Path:
    """
    Encrypt a file to an .aegis container.
    Defaults output to <input_path>.aegis.
    Safe failure: writes to temporary file and renames atomically on success.
    """
    inp = Path(input_path).resolve()
    if not inp.is_file():
        raise FileNotFoundError(f"Input file not found: {inp}")

    if output_path is None:
        outp = inp.with_name(inp.name + ".aegis")
    else:
        outp = Path(output_path).resolve()

    total_size = inp.stat().st_size
    temp_out = outp.parent / f".{outp.name}.tmp_{os.urandom(6).hex()}"

    try:
        with open(inp, "rb") as f_in, open(temp_out, "wb") as f_out:
            encrypt_stream(
                f_in,
                f_out,
                password=password,
                chunk_size=chunk_size,
                kdf_params=kdf_params,
                progress_callback=progress_callback,
                total_size=total_size,
            )
        temp_out.replace(outp)
        return outp
    except Exception:
        if temp_out.exists():
            try:
                temp_out.unlink()
            except OSError:
                pass
        raise


def decrypt_file(
    input_path: str | Path,
    output_path: Optional[str | Path] = None,
    password: str | bytes = "",
    progress_callback: Optional[ProgressCallback] = None,
) -> Path:
    """
    Decrypt an .aegis container.
    If output_path is omitted, strips .aegis suffix if present or appends .decrypted.
    Fails closed: outputs nothing if authentication or integrity verification fails.
    """
    inp = Path(input_path).resolve()
    if not inp.is_file():
        raise FileNotFoundError(f"Input file not found: {inp}")

    if output_path is None:
        if inp.name.endswith(".aegis"):
            outp = inp.with_name(inp.name[:-6])
        else:
            outp = inp.with_name(inp.name + ".decrypted")
    else:
        outp = Path(output_path).resolve()

    total_size = inp.stat().st_size
    temp_out = outp.parent / f".{outp.name}.tmp_{os.urandom(6).hex()}"

    try:
        with open(inp, "rb") as f_in, open(temp_out, "wb") as f_out:
            decrypt_stream(
                f_in,
                f_out,
                password=password,
                progress_callback=progress_callback,
                total_size=total_size,
            )
        # Verify complete and atomically place output file
        temp_out.replace(outp)
        return outp
    except Exception:
        # Strict fail closed: remove temporary file
        if temp_out.exists():
            try:
                temp_out.unlink()
            except OSError:
                pass
        raise
