"""
SHA-256 Hashing & Integrity Module
==================================
Provides cryptographic hashing using Secure Hash Algorithm 256-bit (SHA-256).
SHA-256 produces a fixed-size 256-bit (32-byte / 64-hex character) digest.

Properties:
- Deterministic: Same input produces the exact same hash.
- Pre-image resistance (One-way): Infeasible to invert the hash to get original input.
- Second pre-image resistance: Infeasible to find a different input with the same hash.
- Collision resistance: Infeasible to find any two different inputs with the same hash.
- Avalanche effect: A 1-bit flip in input flips ~50% of the output hash bits.
"""

import hashlib
import hmac


def calculate_sha256(data_bytes: bytes) -> str:
    """
    Calculate the SHA-256 hexadecimal hash string for arbitrary binary data.
    
    Parameters:
        data_bytes (bytes): Binary input data.
        
    Returns:
        str: 64-character lowercase hex string of the SHA-256 digest.
    """
    hasher = hashlib.sha256()
    hasher.update(data_bytes)
    return hasher.hexdigest()


def calculate_sha256_bytes(data_bytes: bytes) -> bytes:
    """
    Calculate the raw 32-byte binary SHA-256 digest.
    """
    hasher = hashlib.sha256()
    hasher.update(data_bytes)
    return hasher.digest()


def verify_sha256(data_bytes: bytes, expected_hash_hex: str) -> bool:
    """
    Verify integrity of data by recomputing SHA-256 and comparing with expected hash.
    Uses constant-time comparison (hmac.compare_digest) to prevent timing attacks.
    
    Parameters:
        data_bytes (bytes): Data to verify.
        expected_hash_hex (str): Original expected SHA-256 hex string.
        
    Returns:
        bool: True if hashes match exactly, False otherwise.
    """
    actual_hash = calculate_sha256(data_bytes)
    return hmac.compare_digest(actual_hash.lower(), expected_hash_hex.lower())
