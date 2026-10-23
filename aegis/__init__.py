"""
Aegis Vault: Local-first authenticated file encryption vault with built-in AES teaching lab.
"""

from aegis.container import ContainerHeader, KeySlot
from aegis.engine import decrypt_file, decrypt_stream, encrypt_file, encrypt_stream
from aegis.errors import (
    AegisError,
    AuthenticationError,
    CorruptContainerError,
    InvalidHeaderError,
    SlotError,
    SlotNotFoundError,
    TamperError,
    UnsupportedVersionError,
)
from aegis.kdf import KDFParams, derive_key, generate_salt
from aegis.slots import add_key_slot, inspect_file, remove_key_slot

__version__ = "0.1.0"

__all__ = [
    "ContainerHeader",
    "KeySlot",
    "encrypt_file",
    "decrypt_file",
    "encrypt_stream",
    "decrypt_stream",
    "inspect_file",
    "add_key_slot",
    "remove_key_slot",
    "KDFParams",
    "derive_key",
    "generate_salt",
    "AegisError",
    "AuthenticationError",
    "TamperError",
    "CorruptContainerError",
    "InvalidHeaderError",
    "UnsupportedVersionError",
    "SlotError",
    "SlotNotFoundError",
]
