"""
AES-256-GCM (Galois/Counter Mode) Module
=======================================
Galois/Counter Mode (GCM) is an Authenticated Encryption with Associated Data (AEAD)
mode for symmetric block ciphers. It provides both confidentiality (via Counter mode)
and integrity/authenticity (via a Galois field multiplication MAC tag).

CNS Mini Project Specifications:
- Key Length: 256 bits (32 bytes) - Maximum security against brute force.
- Nonce Length: 96 bits (12 bytes) - Recommended standard length for GCM to avoid GHASH overhead.
- Authentication Tag: 128 bits (16 bytes) - Appended to ciphertext to guarantee message authenticity.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def generate_aes_key() -> bytes:
    """
    Generate a cryptographically secure random 256-bit (32 bytes) AES key.
    Uses the operating system's CSPRNG (os.urandom).
    """
    return AESGCM.generate_key(bit_length=256)


def generate_nonce() -> bytes:
    """
    Generate a cryptographically secure random 96-bit (12 bytes) Nonce (IV).
    A fresh nonce MUST be generated for each encryption operation under the same key.
    """
    return os.urandom(12)


def encrypt_file(plaintext_bytes: bytes, key: bytes, associated_data: bytes = None) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt file data using AES-256-GCM.
    
    Parameters:
        plaintext_bytes (bytes): The raw file payload to be encrypted.
        key (bytes): 256-bit (32 bytes) AES key.
        associated_data (bytes, optional): Additional authenticated data (AAD) not encrypted but authenticated.
        
    Returns:
        tuple (nonce, ciphertext, auth_tag):
            nonce (12 bytes): Unique IV used for encryption.
            ciphertext (bytes): Encrypted file bytes.
            auth_tag (16 bytes): 128-bit authentication tag produced by GHASH.
    """
    if len(key) != 32:
        raise ValueError(f"AES key must be exactly 32 bytes (256 bits), got {len(key)} bytes.")
    
    nonce = generate_nonce()
    aesgcm = AESGCM(key)
    
    # AESGCM.encrypt appends the 16-byte authentication tag to the ciphertext
    combined_ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)
    
    # Separate ciphertext payload and 16-byte authentication tag
    ciphertext = combined_ciphertext[:-16]
    auth_tag = combined_ciphertext[-16:]
    
    return nonce, ciphertext, auth_tag


def decrypt_file(nonce: bytes, ciphertext: bytes, auth_tag: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    """
    Decrypt file data using AES-256-GCM and verify its authenticity tag.
    
    Parameters:
        nonce (bytes): The 12-byte IV used during encryption.
        ciphertext (bytes): The encrypted file payload.
        auth_tag (bytes): The 16-byte authentication tag.
        key (bytes): 256-bit (32 bytes) AES key.
        associated_data (bytes, optional): AAD passed during encryption.
        
    Returns:
        bytes: The recovered original plaintext file bytes.
        
    Raises:
        InvalidTag: If the ciphertext, tag, nonce, or key has been tampered with.
    """
    if len(key) != 32:
        raise ValueError(f"AES key must be exactly 32 bytes (256 bits), got {len(key)} bytes.")
    if len(nonce) != 12:
        raise ValueError(f"Nonce must be exactly 12 bytes (96 bits), got {len(nonce)} bytes.")
    if len(auth_tag) != 16:
        raise ValueError(f"Auth tag must be exactly 16 bytes (128 bits), got {len(auth_tag)} bytes.")
    
    aesgcm = AESGCM(key)
    # Reassemble ciphertext + tag as required by cryptography library
    combined_ciphertext = ciphertext + auth_tag
    
    try:
        plaintext = aesgcm.decrypt(nonce, combined_ciphertext, associated_data)
        return plaintext
    except InvalidTag as e:
        raise ValueError("AES-GCM Authentication Failed: Data has been tampered with or key is invalid!") from e
