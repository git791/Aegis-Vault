"""
Aegis container format parser, serializer, and key slot management.

Container layout:
  magic "AEGIS" (5B) | version (1B) | header_len (4B) | header JSON | chunks...
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, BinaryIO, Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aegis.errors import (
    AuthenticationError,
    CorruptContainerError,
    InvalidHeaderError,
    SlotError,
    SlotNotFoundError,
    UnsupportedVersionError,
)
from aegis.kdf import KDFParams, derive_key, generate_salt

MAGIC = b"AEGIS"
CURRENT_VERSION = 1
SUPPORTED_VERSIONS = {1}
MAX_HEADER_SIZE = 64 * 1024  # 64 KiB safe upper bound against memory bombs
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB chunks
SLOT_AAD_PREFIX = b"AEGIS_SLOT_V1"


@dataclass
class KeySlot:
    """Represents a password slot encrypting the master file key."""
    slot_id: int
    label: str
    salt: bytes
    kdf_params: KDFParams
    nonce: bytes  # 12 bytes AES-GCM nonce
    wrapped_key: bytes  # 32 bytes ciphertext + 16 bytes auth tag

    def to_dict(self) -> Dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "label": self.label,
            "salt": self.salt.hex(),
            "kdf": self.kdf_params.to_dict(),
            "nonce": self.nonce.hex(),
            "wrapped_key": self.wrapped_key.hex(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KeySlot:
        try:
            return cls(
                slot_id=int(data["slot_id"]),
                label=str(data.get("label", f"slot_{data['slot_id']}")),
                salt=bytes.fromhex(data["salt"]),
                kdf_params=KDFParams.from_dict(data["kdf"]),
                nonce=bytes.fromhex(data["nonce"]),
                wrapped_key=bytes.fromhex(data["wrapped_key"]),
            )
        except (KeyError, ValueError, TypeError) as e:
            raise InvalidHeaderError(f"Malformed key slot in header: {e}") from e

    def unwrap(self, password: str | bytes) -> bytes:
        """
        Derive slot key and unwrap the 32-byte master file key.
        Raises AuthenticationError if password or slot tag fails.
        """
        slot_key = derive_key(password, self.salt, self.kdf_params)
        aesgcm = AESGCM(slot_key)
        aad = SLOT_AAD_PREFIX + struct.pack(">I", self.slot_id)
        try:
            file_key = aesgcm.decrypt(self.nonce, self.wrapped_key, aad)
            if len(file_key) != 32:
                raise AuthenticationError("Decrypted file key has invalid length")
            return file_key
        except InvalidTag:
            raise AuthenticationError("Incorrect password or corrupt key slot")

    @classmethod
    def create(
        cls,
        slot_id: int,
        password: str | bytes,
        file_key: bytes,
        label: str = "primary",
        kdf_params: Optional[KDFParams] = None,
    ) -> KeySlot:
        """Create a new KeySlot wrapping the given file_key."""
        if kdf_params is None:
            kdf_params = KDFParams()
        salt = generate_salt(16)
        slot_key = derive_key(password, salt, kdf_params)
        nonce = os.urandom(12)
        aad = SLOT_AAD_PREFIX + struct.pack(">I", slot_id)
        aesgcm = AESGCM(slot_key)
        wrapped_key = aesgcm.encrypt(nonce, file_key, aad)
        return cls(
            slot_id=slot_id,
            label=label,
            salt=salt,
            kdf_params=kdf_params,
            nonce=nonce,
            wrapped_key=wrapped_key,
        )


@dataclass
class ContainerHeader:
    """Header information stored at the start of an .aegis container."""
    version: int
    stream_id: bytes  # 16-byte random unique identifier for this encryption stream
    nonce_prefix: bytes  # 8-byte random prefix for chunk nonces
    chunk_size: int = DEFAULT_CHUNK_SIZE
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    slots: List[KeySlot] = field(default_factory=list)

    def compute_stream_binding(self) -> bytes:
        """
        Deterministic SHA-256 digest binding immutable stream parameters.
        Included in AAD for every chunk to detect tampering or transposition.
        """
        payload = (
            b"AEGIS_STREAM_V1:"
            + struct.pack(">B", self.version)
            + struct.pack(">I", self.chunk_size)
            + self.nonce_prefix
            + self.stream_id
        )
        return hashlib.sha256(payload).digest()

    def serialize(self) -> bytes:
        """Serialize complete container header (magic + version + length + JSON)."""
        data = {
            "version": self.version,
            "stream_id": self.stream_id.hex(),
            "nonce_prefix": self.nonce_prefix.hex(),
            "chunk_size": self.chunk_size,
            "created_at": self.created_at,
            "slots": [slot.to_dict() for slot in self.slots],
        }
        json_bytes = json.dumps(data, indent=None, separators=(",", ":")).encode("utf-8")
        if len(json_bytes) > MAX_HEADER_SIZE:
            raise InvalidHeaderError(f"Header size ({len(json_bytes)} bytes) exceeds maximum {MAX_HEADER_SIZE}")
        
        prefix = MAGIC + struct.pack(">BI", self.version, len(json_bytes))
        return prefix + json_bytes

    @classmethod
    def read_from_stream(cls, stream: BinaryIO) -> Tuple[ContainerHeader, int]:
        """
        Read and parse the container header from a stream.
        Returns (header, header_total_bytes_read).
        """
        prefix_len = len(MAGIC) + 1 + 4
        prefix = stream.read(prefix_len)
        if len(prefix) < prefix_len:
            raise CorruptContainerError("File is too short to be a valid Aegis container")

        magic = prefix[:5]
        if magic != MAGIC:
            raise CorruptContainerError(f"Invalid magic: expected {MAGIC!r}, got {magic!r}")

        version, header_len = struct.unpack(">BI", prefix[5:10])
        if version not in SUPPORTED_VERSIONS:
            raise UnsupportedVersionError(f"Unsupported Aegis container version: {version}")

        if header_len > MAX_HEADER_SIZE:
            raise InvalidHeaderError(
                f"Header length ({header_len} bytes) exceeds safety limit ({MAX_HEADER_SIZE} bytes)"
            )

        json_bytes = stream.read(header_len)
        if len(json_bytes) < header_len:
            raise CorruptContainerError("Truncated header in Aegis container")

        try:
            data = json.loads(json_bytes.decode("utf-8"))
        except Exception as e:
            raise InvalidHeaderError(f"Malformed JSON in Aegis header: {e}") from e

        json_ver = data.get("version")
        if json_ver is not None and json_ver != version:
            raise InvalidHeaderError(f"Header version mismatch: container is v{version}, JSON is v{json_ver}")

        try:
            stream_id = bytes.fromhex(data["stream_id"])
            nonce_prefix = bytes.fromhex(data["nonce_prefix"])
            chunk_size = int(data.get("chunk_size", DEFAULT_CHUNK_SIZE))
            created_at = str(data.get("created_at", ""))
            slots_data = data.get("slots", [])
            slots = [KeySlot.from_dict(s) for s in slots_data]
        except (KeyError, ValueError, TypeError) as e:
            raise InvalidHeaderError(f"Invalid header structure: {e}") from e

        header = cls(
            version=version,
            stream_id=stream_id,
            nonce_prefix=nonce_prefix,
            chunk_size=chunk_size,
            created_at=created_at,
            slots=slots,
        )
        return header, prefix_len + header_len

    def unlock_file_key(self, password: str | bytes) -> bytes:
        """
        Try unlocking the file key across all available slots.
        Raises AuthenticationError if no slot unlocks.
        """
        if not self.slots:
            raise SlotError("No key slots available in container")

        for slot in self.slots:
            try:
                return slot.unwrap(password)
            except AuthenticationError:
                continue

        raise AuthenticationError("Incorrect password")

    def add_slot(
        self,
        current_password: str | bytes,
        new_password: str | bytes,
        label: str = "",
        kdf_params: Optional[KDFParams] = None,
    ) -> KeySlot:
        """Add a new password slot to the container."""
        file_key = self.unlock_file_key(current_password)
        next_slot_id = max((s.slot_id for s in self.slots), default=-1) + 1
        slot_label = label if label else f"slot_{next_slot_id}"
        new_slot = KeySlot.create(
            slot_id=next_slot_id,
            password=new_password,
            file_key=file_key,
            label=slot_label,
            kdf_params=kdf_params,
        )
        self.slots.append(new_slot)
        return new_slot

    def remove_slot(
        self,
        slot_id: int,
        password: str | bytes,
    ) -> None:
        """Remove a password slot from the container (requires verification password)."""
        # Verification to ensure caller has valid access
        self.unlock_file_key(password)
        if len(self.slots) <= 1:
            raise SlotError("Cannot remove the last remaining key slot from container")

        for idx, slot in enumerate(self.slots):
            if slot.slot_id == slot_id:
                del self.slots[idx]
                return

        raise SlotNotFoundError(f"Key slot with ID {slot_id} not found")
