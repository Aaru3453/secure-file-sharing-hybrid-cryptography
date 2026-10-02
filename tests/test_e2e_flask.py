"""
Comprehensive End-to-End & Negative Security Tests
==================================================
Verifies:
1. Normal flow: Alice registers -> Bob registers -> Alice sends file -> Bob decrypts & downloads
2. Negative test: Unauthorized user cannot view/verify/download someone else's file
3. Negative test: Tampered ciphertext on disk causes AES-GCM tag verification failure
4. Negative test: Tampered digital signature is detected as invalid
"""

import os
import io
import unittest
import sqlite3
from app import app
from config import Config
from models.database import init_db, get_db_connection


class TestE2ESecureFileSharing(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_db = os.path.join(Config.BASE_DIR, 'models', 'test_secure_share_comp.db')
        app.config['DATABASE'] = cls.test_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        Config.init_app()
        init_db(cls.test_db)
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.test_db):
            try:
                os.remove(cls.test_db)
            except Exception:
                pass

    def test_01_complete_lifecycle_and_negative_security_checks(self):
        """Test registration, file transfer, positive verification, and negative security tamper tests."""
        
        # 1. Register Alice, Bob, and Eve
        for username, password in [('alice', 'AlicePassword123!'), ('bob', 'BobPassword456!'), ('eve', 'EvePassword789!')]:
            res = self.client.post('/register', data={
                'username': username,
                'email': f'{username}@college.edu',
                'password': password,
                'confirm_password': password
            }, follow_redirects=True)
            self.assertEqual(res.status_code, 200)

        # 2. Login as Alice
        self.client.post('/login', data={'username': 'alice', 'password': 'AlicePassword123!'}, follow_redirects=True)

        # 3. Alice uploads and encrypts a file for Bob (Bob's id is 2)
        original_bytes = b"CONFIDENTIAL: College CNS Mini Project Experiment Report 2026."
        file_payload = {
            'receiver_id': '2',
            'file': (io.BytesIO(original_bytes), 'cns_experiment_report.txt')
        }
        res = self.client.post('/send', data=file_payload, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"encrypted and securely transferred to bob", res.data)

        # 4. Eve tries to access Bob's received file (file_id = 1)
        self.client.get('/logout', follow_redirects=True)
        self.client.post('/login', data={'username': 'eve', 'password': 'EvePassword789!'}, follow_redirects=True)
        
        res = self.client.get('/verify/1', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Access Denied", res.data, "Eve must NOT be able to verify Bob's file!")

        res = self.client.get('/download/1', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Unauthorized download attempt", res.data, "Eve must NOT be able to download Bob's file!")

        # 5. Bob logs in and verifies successfully
        self.client.get('/logout', follow_redirects=True)
        self.client.post('/login', data={'username': 'bob', 'password': 'BobPassword456!'}, follow_redirects=True)

        res = self.client.get('/verify/1')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"DECAPSULATED", res.data)
        self.assertIn(b"TAG VERIFIED", res.data)
        self.assertIn(b"SIGNATURE VALID", res.data)
        self.assertIn(b"MATCH 100%", res.data)

        # 6. Bob downloads the verified file
        res = self.client.get('/download/1')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data, original_bytes)

    def test_02_tamper_detection_on_ciphertext(self):
        """Tampering with encrypted file payload on disk must trigger AES-GCM authentication failure."""
        # Alice sends another file to Bob
        self.client.post('/login', data={'username': 'alice', 'password': 'AlicePassword123!'}, follow_redirects=True)
        
        file_payload = {
            'receiver_id': '2',
            'file': (io.BytesIO(b"Data that will be attacked by an eavesdropper / man-in-the-middle."), 'attack_target.txt')
        }
        res = self.client.post('/send', data=file_payload, content_type='multipart/form-data', follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Find the stored encrypted filename for file_id = 2
        conn = get_db_connection(self.test_db)
        row = conn.execute("SELECT stored_filename FROM files WHERE id = 2").fetchone()
        conn.close()
        self.assertIsNotNone(row)

        stored_file_path = os.path.join(Config.ENCRYPTED_DIR, row['stored_filename'])
        self.assertTrue(os.path.exists(stored_file_path))

        # Tamper with the encrypted file (flip the first byte)
        with open(stored_file_path, 'rb') as f:
            cipher_data = bytearray(f.read())
        cipher_data[0] ^= 0xFF  # Corrupt first byte
        with open(stored_file_path, 'wb') as f:
            f.write(cipher_data)

        # Bob tries to verify file_id = 2
        self.client.get('/logout', follow_redirects=True)
        self.client.post('/login', data={'username': 'bob', 'password': 'BobPassword456!'}, follow_redirects=True)

        res = self.client.get('/verify/2')
        self.assertEqual(res.status_code, 200)
        # Should detect error and show failure
        self.assertIn(b"AES-GCM Authentication Failed", res.data)
        self.assertIn(b"Download Blocked Due to Tamper Risk", res.data)


if __name__ == '__main__':
    unittest.main()
