"""
RSA-PSS Digital Signature Module
================================
Implements Digital Signatures using RSA-PSS (Probabilistic Signature Scheme)
with SHA-256 hash algorithm.

Key Features:
- Non-Repudiation: Sender cannot deny sending the file.
- Authentication: Receiver verifies the exact sender identity.
- Data Integrity: Any modification to signed metadata or payload invalidates the signature.
- PSS Padding: Randomized salt avoids mathematical vulnerabilities inherent in deterministic PKCS#1 v1.5.
"""

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from crypto.rsa import load_private_key, load_public_key


def create_signature(data_bytes: bytes, sender_private_key_pem: str, password: str = None) -> bytes:
    """
    Sign arbitrary data using the sender's RSA-2048 private key with RSA-PSS and SHA-256.
    
    Parameters:
        data_bytes (bytes): The data (typically file hash or canonical package summary) to sign.
        sender_private_key_pem (str): Sender's PEM encoded private key.
        password (str, optional): Password for encrypted private key.
        
    Returns:
        bytes: 256-byte digital signature.
    """
    private_key = load_private_key(sender_private_key_pem, password)
    
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data_bytes: bytes, signature_bytes: bytes, sender_public_key_pem: str) -> bool:
    """
    Verify a digital signature using the sender's RSA-2048 public key.
    
    Parameters:
        data_bytes (bytes): The original signed data.
        signature_bytes (bytes): The 256-byte signature to verify.
        sender_public_key_pem (str): Sender's PEM encoded public key.
        
    Returns:
        bool: True if signature is cryptographically valid, False if invalid or tampered.
    """
    try:
        public_key = load_public_key(sender_public_key_pem)
        public_key.verify(
            signature_bytes,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def build_signature_payload(original_sha256: str, original_filename: str, sender_id: int, receiver_id: int) -> bytes:
    """
    Canonical representation of package metadata to be signed.
    Binding file hash with filename and receiver prevents replay and substitution attacks.
    """
    canonical_string = f"CNS-SHARE:v1|hash={original_sha256}|file={original_filename}|from={sender_id}|to={receiver_id}"
    return canonical_string.encode('utf-8')
