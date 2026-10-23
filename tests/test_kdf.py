"""
Tests for Argon2id Key Derivation Function wrapper.
"""

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from aegis.errors import AuthenticationError
from aegis.kdf import (
    KDFParams,
    benchmark_kdf,
    derive_key,
    generate_salt,
    verify_key,
)


def test_generate_salt():
    salt1 = generate_salt(16)
    salt2 = generate_salt(16)
    assert len(salt1) == 16
    assert len(salt2) == 16
    assert salt1 != salt2


def test_derive_key_determinism():
    salt = b"test_salt_123456"
    pwd = "CorrectHorseBatteryStaple"
    # Use fast params for tests
    params = KDFParams(iterations=1, memory_cost=8192, lanes=1, key_len=32)

    key1 = derive_key(pwd, salt, params)
    key2 = derive_key(pwd, salt, params)
    assert key1 == key2
    assert len(key1) == 32


def test_different_salt_different_key():
    pwd = "SecretPassword123"
    params = KDFParams(iterations=1, memory_cost=8192, lanes=1, key_len=32)

    key1 = derive_key(pwd, b"salt_one_1234567", params)
    key2 = derive_key(pwd, b"salt_two_1234567", params)
    assert key1 != key2


def test_different_password_different_key():
    salt = b"test_salt_123456"
    params = KDFParams(iterations=1, memory_cost=8192, lanes=1, key_len=32)

    key1 = derive_key("PasswordOne", salt, params)
    key2 = derive_key("PasswordTwo", salt, params)
    assert key1 != key2


def test_verify_key():
    salt = b"test_salt_123456"
    pwd = "VerifyMePassword"
    params = KDFParams(iterations=1, memory_cost=8192, lanes=1, key_len=32)
    key = derive_key(pwd, salt, params)

    assert verify_key(pwd, salt, key, params) is True

    with pytest.raises(AuthenticationError):
        verify_key("WrongPassword", salt, key, params)


def test_salt_too_short():
    with pytest.raises(ValueError, match="at least 16 bytes"):
        derive_key("pwd", b"short", KDFParams())


def test_benchmark_kdf():
    duration = benchmark_kdf(iterations=1, memory_cost=8192, lanes=1)
    assert duration > 0.0
