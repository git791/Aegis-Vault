"""
Argon2id Key Derivation Function wrapper (RFC 9106).
Uses OpenSSL-backed Argon2id from the `cryptography` library.
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from aegis.errors import AuthenticationError


# Recommended default parameters (OWASP / RFC 9106 compliant for interactive file vaults)
# 64 MiB memory, 2 iterations, 1 lane, 32-byte key
DEFAULT_ITERATIONS = 2
DEFAULT_MEMORY_COST = 65536  # KiB (64 MiB)
DEFAULT_LANES = 1
DEFAULT_KEY_LEN = 32  # 256-bit key for AES-256
DEFAULT_SALT_SIZE = 16  # 128-bit random salt


@dataclass(frozen=True)
class KDFParams:
    """Argon2id derivation parameters stored in the container header."""
    algorithm: str = "argon2id"
    iterations: int = DEFAULT_ITERATIONS
    memory_cost: int = DEFAULT_MEMORY_COST  # KiB
    lanes: int = DEFAULT_LANES
    key_len: int = DEFAULT_KEY_LEN

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KDFParams:
        algo = data.get("algorithm", "argon2id").lower()
        if algo != "argon2id":
            raise ValueError(f"Unsupported KDF algorithm: {algo}")
        return cls(
            algorithm="argon2id",
            iterations=int(data.get("iterations", data.get("time_cost", DEFAULT_ITERATIONS))),
            memory_cost=int(data.get("memory_cost", DEFAULT_MEMORY_COST)),
            lanes=int(data.get("lanes", data.get("parallelism", DEFAULT_LANES))),
            key_len=int(data.get("key_len", DEFAULT_KEY_LEN)),
        )


def generate_salt(size: int = DEFAULT_SALT_SIZE) -> bytes:
    """Generate cryptographically secure random salt."""
    return os.urandom(size)


def derive_key(
    password: str | bytes,
    salt: bytes,
    params: KDFParams | None = None,
) -> bytes:
    """
    Derive a 256-bit key from a password and salt using Argon2id.
    
    Args:
        password: Plaintext password as string or bytes.
        salt: Random salt bytes (minimum 16 bytes).
        params: KDF configuration parameters.
        
    Returns:
        32-byte derived key.
    """
    if params is None:
        params = KDFParams()

    if isinstance(password, str):
        pwd_bytes = password.encode("utf-8")
    else:
        pwd_bytes = password

    if len(salt) < 16:
        raise ValueError("Salt must be at least 16 bytes")

    kdf = Argon2id(
        salt=salt,
        length=params.key_len,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_cost,
    )
    return kdf.derive(pwd_bytes)


def verify_key(
    password: str | bytes,
    salt: bytes,
    expected_key: bytes,
    params: KDFParams | None = None,
) -> bool:
    """
    Constant-time verification of a password against an expected key.
    Raises AuthenticationError if invalid.
    """
    if params is None:
        params = KDFParams()

    if isinstance(password, str):
        pwd_bytes = password.encode("utf-8")
    else:
        pwd_bytes = password

    kdf = Argon2id(
        salt=salt,
        length=params.key_len,
        iterations=params.iterations,
        lanes=params.lanes,
        memory_cost=params.memory_cost,
    )
    try:
        kdf.verify(pwd_bytes, expected_key)
        return True
    except InvalidKey:
        raise AuthenticationError("Incorrect password or corrupted key")


def benchmark_kdf(
    iterations: int = DEFAULT_ITERATIONS,
    memory_cost: int = DEFAULT_MEMORY_COST,
    lanes: int = DEFAULT_LANES,
) -> float:
    """
    Benchmark Argon2id execution time on the current host.
    Returns duration in seconds.
    """
    salt = b"\x00" * 16
    pwd = b"benchmark_password_string"
    start = time.perf_counter()
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=iterations,
        lanes=lanes,
        memory_cost=memory_cost,
    )
    kdf.derive(pwd)
    return time.perf_counter() - start
