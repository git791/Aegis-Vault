"""
Password Lab: Password strength evaluation and brute-force cost analysis.
Provides entropy calculations, pattern detection, and realistic hardware cracking estimates
comparing fast hashes against memory-hard Argon2id.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List

COMMON_PATTERNS = [
    r"^[a-zA-Z]+$",
    r"^[0-9]+$",
    r"(.)\1{2,}",  # 3 or more repeated characters
    r"12345|23456|34567|45678|56789",
    r"qwerty|asdfgh|zxcvbn",
    r"password|admin|welcome|letmein|monkey|dragon",
]


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy bits based on character pool and length."""
    if not password:
        return 0.0

    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password):
        pool += 33
    if any(ord(c) > 127 for c in password):
        pool += 50

    if pool == 0:
        return 0.0

    # Theoretical entropy in bits: len * log2(pool)
    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 1e-4:
        return "Instant"
    if seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 86400 * 365:
        return f"{seconds / 86400:.1f} days"
    years = seconds / (86400 * 365)
    if years < 1000:
        return f"{years:.1f} years"
    if years < 1e6:
        return f"{years / 1e3:.1f} thousand years"
    if years < 1e9:
        return f"{years / 1e6:.1f} million years"
    return "Centuries (effectively uncrackable)"


def analyze_password(password: str) -> Dict[str, Any]:
    """
    Perform deep analysis of a password's security.
    Returns score (0-4), entropy, pattern flags, and estimated brute-force times.
    """
    length = len(password)
    entropy = calculate_entropy(password)

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password))

    patterns_found = []
    lower_pwd = password.lower()
    for pat in COMMON_PATTERNS:
        if re.search(pat, lower_pwd):
            patterns_found.append(pat)

    # Compute score (0 to 4)
    score = 0
    if length >= 8:
        score += 1
    if length >= 14:
        score += 1
    if (has_lower and has_upper) and (has_digit or has_symbol):
        score += 1
    if entropy >= 60 and len(patterns_found) == 0:
        score += 1

    # Penalties
    if length < 6:
        score = 0
    elif len(patterns_found) >= 2 and score > 1:
        score -= 1

    score = max(0, min(4, score))

    labels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
    label = labels[score]

    # Brute-force space calculation: 2^entropy combinations
    # Average crack time is expected search through half the keyspace (2^(entropy - 1))
    keyspace = 2 ** entropy if entropy < 256 else 2**256
    half_keyspace = keyspace / 2.0

    # Hardware scenarios:
    # 1. Fast online guessing (throttled): 100 attempts / sec
    online_rate = 100.0
    # 2. Fast unsalted / PBKDF2 hash on 8x RTX 4090 GPU cluster: 10^10 hashes / sec
    gpu_fast_rate = 1e10
    # 3. Argon2id (64 MiB, 2 iterations):
    # An RTX 4090 (24GB VRAM) can run at most 24000/64 ~ 375 parallel instances, ~2,000 hashes/sec
    argon2id_rate = 2000.0

    online_time = format_duration(half_keyspace / online_rate)
    gpu_fast_time = format_duration(half_keyspace / gpu_fast_rate)
    argon2id_time = format_duration(half_keyspace / argon2id_rate)

    suggestions: List[str] = []
    if length < 12:
        suggestions.append("Make your password at least 12-16 characters long.")
    if not (has_lower and has_upper):
        suggestions.append("Combine uppercase and lowercase letters.")
    if not has_digit:
        suggestions.append("Include numbers.")
    if not has_symbol:
        suggestions.append("Include special symbols (!@#$%^&*).")
    if patterns_found:
        suggestions.append("Avoid obvious dictionary words or sequential characters (e.g. 12345).")
    if not suggestions:
        suggestions.append("Great password! Memory-hard Argon2id will protect it against GPU clusters.")

    return {
        "password_length": length,
        "entropy_bits": entropy,
        "score": score,
        "label": label,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digit,
        "has_symbols": has_symbol,
        "patterns_detected": len(patterns_found) > 0,
        "estimates": {
            "online_throttled": {
                "rate": "100 guesses/sec",
                "time": online_time,
            },
            "gpu_fast_hash": {
                "rate": "10,000,000,000 / sec (PBKDF2/MD5 GPU cluster)",
                "time": gpu_fast_time,
            },
            "argon2id_vault": {
                "rate": "2,000 / sec (Argon2id 64MB memory-hard)",
                "time": argon2id_time,
                "advantage": "Argon2id's 64MB RAM requirement exhausts GPU memory, making brute-force ~5,000,000x harder than PBKDF2.",
            },
        },
        "suggestions": suggestions,
    }
