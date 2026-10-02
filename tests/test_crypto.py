"""
Unit Tests for Hybrid Cryptography System
=========================================
Tests:
- AES-256-GCM encryption/decryption and authentication tag integrity
- RSA-2048 keypair generation and OAEP key encapsulation
- SHA-256 integrity calculation and verification
- RSA-PSS digital signing and verification
- Tamper detection tests
"""

import os
import unittest
from crypto.aes import generate_aes_key, generate_nonce, encrypt_file, decrypt_file
from crypto.rsa import generate_rsa_keypair, encrypt_aes_key, decrypt_aes_key
from crypto.hashing import calculate_sha256, verify_sha256
from crypto.signatures import create_signature, verify_signature, build_signature_payload


class TestHybridCryptography(unittest.TestCase):

    def setUp(self):
        self.test_payload = b"Top Secret Exam Paper / CNS Mini Project Test Data 2026! Nonce and Key check."
        self.user_password = "AliceStrongPassword123!"

    def test_aes_gcm_encrypt_decrypt(self):
        """Test AES-256-GCM encryption, decryption, and authentication tag."""
        key = generate_aes_key()
        self.assertEqual(len(key), 32, "AES-256 key must be 32 bytes.")
        
        nonce, ciphertext, auth_tag = encrypt_file(self.test_payload, key)
        self.assertEqual(len(nonce), 12, "GCM nonce must be 12 bytes.")
        self.assertEqual(len(auth_tag), 16, "GCM auth tag must be 16 bytes.")
        self.assertNotEqual(ciphertext, self.test_payload, "Ciphertext must not equal plaintext.")
        
        # Successful Decryption
        decrypted = decrypt_file(nonce, ciphertext, auth_tag, key)
        self.assertEqual(decrypted, self.test_payload, "Decrypted data must match original plaintext.")

    def test_aes_gcm_tamper_detection(self):
        """Test that modifying even 1 bit in ciphertext causes GCM authentication failure."""
        key = generate_aes_key()
        nonce, ciphertext, auth_tag = encrypt_file(self.test_payload, key)
        
        # Flip first byte of ciphertext
        tampered_ciphertext = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
        
        with self.assertRaises(ValueError):
            decrypt_file(nonce, tampered_ciphertext, auth_tag, key)

    def test_rsa_oaep_key_encapsulation(self):
        """Test RSA-2048 OAEP encryption and decryption of 256-bit AES key."""
        priv_pem, pub_pem = generate_rsa_keypair(self.user_password)
        aes_key = generate_aes_key()
        
        # Encrypt AES key using Public Key
        encrypted_aes_key = encrypt_aes_key(aes_key, pub_pem)
        self.assertEqual(len(encrypted_aes_key), 256, "RSA-2048 ciphertext must be 256 bytes.")
        
        # Decrypt AES key using Private Key
        recovered_aes_key = decrypt_aes_key(encrypted_aes_key, priv_pem, self.user_password)
        self.assertEqual(recovered_aes_key, aes_key, "Decrypted AES key must match original AES key.")

    def test_sha256_integrity(self):
        """Test SHA-256 hashing and verification."""
        hash_hex = calculate_sha256(self.test_payload)
        self.assertEqual(len(hash_hex), 64, "SHA-256 hex string must be 64 characters.")
        
        # Verification succeeds
        self.assertTrue(verify_sha256(self.test_payload, hash_hex))
        
        # Verification fails if data is altered
        altered_payload = self.test_payload + b" "
        self.assertFalse(verify_sha256(altered_payload, hash_hex))

    def test_rsa_pss_digital_signature(self):
        """Test RSA-PSS digital signing and verification."""
        priv_pem, pub_pem = generate_rsa_keypair(self.user_password)
        file_hash = calculate_sha256(self.test_payload)
        
        payload_to_sign = build_signature_payload(file_hash, "document.pdf", sender_id=1, receiver_id=2)
        
        # Alice signs
        signature = create_signature(payload_to_sign, priv_pem, self.user_password)
        self.assertEqual(len(signature), 256, "RSA-2048 signature must be 256 bytes.")
        
        # Bob verifies Alice's signature with Alice's public key
        is_valid = verify_signature(payload_to_sign, signature, pub_pem)
        self.assertTrue(is_valid, "Digital signature must verify successfully.")
        
        # Tampered payload fails verification
        tampered_payload = build_signature_payload(file_hash, "tampered_document.pdf", sender_id=1, receiver_id=2)
        self.assertFalse(verify_signature(tampered_payload, signature, pub_pem))

    def test_full_hybrid_cryptosystem_workflow(self):
        """
        Simulate the complete Alice -> Bob transmission:
        1. Alice generates AES key & nonce, encrypts payload.
        2. Alice encrypts AES key with Bob's public key.
        3. Alice computes SHA-256 hash of plaintext.
        4. Alice signs package metadata with her private key.
        5. Bob decrypts AES key with his private key.
        6. Bob decrypts payload with recovered AES key.
        7. Bob verifies Alice's signature using Alice's public key.
        8. Bob recomputes SHA-256 and validates integrity.
        """
        # Key pairs
        alice_priv, alice_pub = generate_rsa_keypair("AlicePass123")
        bob_priv, bob_pub = generate_rsa_keypair("BobPass456")
        
        # Alice encrypts file with random AES key
        aes_key = generate_aes_key()
        nonce, ciphertext, auth_tag = encrypt_file(self.test_payload, aes_key)
        
        # Alice encrypts AES key with Bob's public key
        encrypted_aes_key = encrypt_aes_key(aes_key, bob_pub)
        
        # Alice hashes plaintext and signs metadata
        orig_hash = calculate_sha256(self.test_payload)
        sig_data = build_signature_payload(orig_hash, "report.pdf", sender_id=1, receiver_id=2)
        signature = create_signature(sig_data, alice_priv, "AlicePass123")
        
        # --- Transmission over insecure network ---
        
        # Bob receives package
        # 1. Bob recovers AES key
        bob_recovered_aes_key = decrypt_aes_key(encrypted_aes_key, bob_priv, "BobPass456")
        self.assertEqual(bob_recovered_aes_key, aes_key)
        
        # 2. Bob decrypts file
        recovered_plaintext = decrypt_file(nonce, ciphertext, auth_tag, bob_recovered_aes_key)
        self.assertEqual(recovered_plaintext, self.test_payload)
        
        # 3. Bob verifies Alice's signature
        is_sig_valid = verify_signature(sig_data, signature, alice_pub)
        self.assertTrue(is_sig_valid)
        
        # 4. Bob verifies SHA-256 integrity
        is_integrity_ok = verify_sha256(recovered_plaintext, orig_hash)
        self.assertTrue(is_integrity_ok)


if __name__ == '__main__':
    unittest.main()
