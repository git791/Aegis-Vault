"""
Key slot manipulation and inspection utilities for Aegis Vault containers.
Allows reading container metadata without passwords and adding/removing key slots
without re-encrypting file payload data.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.container import ContainerHeader
from aegis.kdf import KDFParams


def inspect_file(container_path: str | Path) -> Dict[str, Any]:
    """
    Inspect an .aegis container header without requiring a password.
    Returns complete metadata including KDF parameters and key slots.
    """
    p = Path(container_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Container file not found: {p}")

    file_size = p.stat().st_size
    with open(p, "rb") as f:
        header, header_len = ContainerHeader.read_from_stream(f)

    slots_info = []
    for slot in header.slots:
        slots_info.append({
            "slot_id": slot.slot_id,
            "label": slot.label,
            "salt_hex": slot.salt.hex(),
            "kdf": slot.kdf_params.to_dict(),
            "nonce_hex": slot.nonce.hex(),
            "wrapped_key_len": len(slot.wrapped_key),
        })

    payload_size = max(0, file_size - header_len)
    approx_chunks = (payload_size + header.chunk_size + 15) // (header.chunk_size + 16) if payload_size > 0 else 0

    return {
        "file_name": p.name,
        "file_size": file_size,
        "header_length_bytes": header_len,
        "payload_length_bytes": payload_size,
        "approx_chunks": approx_chunks,
        "version": header.version,
        "chunk_size": header.chunk_size,
        "stream_id": header.stream_id.hex(),
        "nonce_prefix": header.nonce_prefix.hex(),
        "created_at": header.created_at,
        "slot_count": len(header.slots),
        "slots": slots_info,
    }


def add_key_slot(
    container_path: str | Path,
    current_password: str | bytes,
    new_password: str | bytes,
    label: str = "",
    kdf_params: Optional[KDFParams] = None,
) -> int:
    """
    Add a new password slot to an existing .aegis container.
    Does not re-encrypt payload chunks.
    Returns the new slot ID.
    """
    p = Path(container_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Container file not found: {p}")

    temp_path = p.parent / f".{p.name}.slot_tmp_{os.urandom(6).hex()}"

    try:
        with open(p, "rb") as f_in:
            header, header_bytes_len = ContainerHeader.read_from_stream(f_in)
            new_slot = header.add_slot(
                current_password=current_password,
                new_password=new_password,
                label=label,
                kdf_params=kdf_params,
            )
            serialized_new_header = header.serialize()

            # Write new header and stream remaining payload chunks unchanged
            with open(temp_path, "wb") as f_out:
                f_out.write(serialized_new_header)
                while True:
                    chunk = f_in.read(64 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)

        temp_path.replace(p)
        return new_slot.slot_id
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise


def remove_key_slot(
    container_path: str | Path,
    slot_id: int,
    password: str | bytes,
) -> None:
    """
    Remove a password slot from an existing .aegis container.
    Requires a valid password to verify authorization.
    """
    p = Path(container_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Container file not found: {p}")

    temp_path = p.parent / f".{p.name}.slot_tmp_{os.urandom(6).hex()}"

    try:
        with open(p, "rb") as f_in:
            header, header_bytes_len = ContainerHeader.read_from_stream(f_in)
            header.remove_slot(slot_id=slot_id, password=password)
            serialized_new_header = header.serialize()

            with open(temp_path, "wb") as f_out:
                f_out.write(serialized_new_header)
                while True:
                    chunk = f_in.read(64 * 1024)
                    if not chunk:
                        break
                    f_out.write(chunk)

        temp_path.replace(p)
    except Exception:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
        raise
