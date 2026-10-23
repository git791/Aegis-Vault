"""
Typed exceptions for Aegis Vault.
All domain-specific errors inherit from AegisError.
"""

class AegisError(Exception):
    """Base exception for all Aegis Vault errors."""
    pass


class AuthenticationError(AegisError):
    """Raised when password is wrong or an authentication tag fails verification."""
    pass


class TamperError(AuthenticationError):
    """Raised when data tampering, reordering, truncation, or corruption is detected."""
    pass


class CorruptContainerError(AegisError):
    """Raised when the container format is malformed or invalid."""
    pass


class InvalidHeaderError(CorruptContainerError):
    """Raised when header size is hostile, invalid JSON, or fields are missing."""
    pass


class UnsupportedVersionError(CorruptContainerError):
    """Raised when container version is not supported by this release."""
    pass


class SlotError(AegisError):
    """Raised for errors in key slot operations."""
    pass


class SlotNotFoundError(SlotError):
    """Raised when a specified key slot does not exist or none could be unlocked."""
    pass


class PasswordRequiredError(AegisError):
    """Raised when an operation requires a password but none was supplied."""
    pass
