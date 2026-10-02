# Secure File Sharing System Using Hybrid Cryptography

A complete, production-grade **Cryptography and Network Security (CNS) Mini Project** built with Python 3, Flask, SQLite, and the Python `cryptography` library.

---

## 📋 Table of Contents
1. [Project Objective & Overview](#-project-objective--overview)
2. [Cryptographic Architecture](#-cryptographic-architecture)
3. [Core Security Primitives & Algorithms](#-core-security-primitives--algorithms)
4. [Sender & Receiver Workflows](#-sender--receiver-workflows)
5. [Project Directory Structure](#-project-directory-structure)
6. [Prerequisites & Installation](#-prerequisites--installation)
7. [Running the Application](#-running-the-application)
8. [Testing & Security Proofs](#-testing--security-proofs)
9. [CNS Mini Project Viva Q&A Guide](#-cns-mini-project-viva-qa-guide)
10. [Future Scope](#-future-scope)

---

## 🎯 Project Objective & Overview

The objective of this project is to implement a secure, end-to-end file sharing system utilizing **Hybrid Cryptography** to fulfill all four fundamental goals of modern information security:
- **Confidentiality:** Unauthorized eavesdroppers cannot read the file contents.
- **Integrity:** Any alteration, truncation, or corruption of the file or metadata is immediately detected.
- **Authenticity:** The receiver verifies that the file originated from the designated sender.
- **Non-Repudiation:** The sender cannot deny having sent the file once digitally signed.

### Why Hybrid Cryptography?
- **Symmetric Ciphers (AES-256-GCM):** Extremely fast at encrypting bulk files with hardware acceleration (AES-NI), but suffers from the *Key Distribution Problem* (how to securely convey the secret key to the receiver).
- **Asymmetric Ciphers (RSA-2048 OAEP):** Solves the key distribution problem using a public/private key pair, but is mathematically intensive and too slow to encrypt large files directly.
- **The Hybrid Solution:** We generate a fresh, random 256-bit AES key for every file, encrypt the file symmetrically with AES-256-GCM, and then encrypt only the small 32-byte AES key using the recipient's RSA-2048 public key.

---

## 🛡️ Cryptographic Architecture

```
                                  SENDER (ALICE)
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
   [Plaintext File]            [Generate AES Key]           [Plaintext File]
           │                     (256-bit CSPRNG)                    │
           │                            │                            │
           │                            ▼                            ▼
           │                   [Encrypt AES Key]             [SHA-256 Hash]
           │                  (with Bob's RSA Pub)                   │
           │                            │                            ▼
           ▼                            ▼                 [RSA-PSS Digital Sig]
    [AES-256-GCM]                       │                 (with Alice's RSA Priv)
  (Unique 96-bit Nonce)                 │                            │
           │                            │                            │
           ▼                            │                            │
[Ciphertext + 128-bit Tag]              │                            │
           │                            │                            │
           └────────────────────────────┼────────────────────────────┘
                                        │
                         Encrypted Transmission Package
                         (Over Insecure Channel / Web)
                                        │
                                  RECEIVER (BOB)
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
  [Decrypt AES Key]           [Verify Digital Sig]           [Decrypt Payload]
 (with Bob's RSA Priv)        (with Alice's RSA Pub)           (AES-256-GCM)
           │                            │                            │
           ▼                            ▼                            ▼
    [AES-256 Key]               [Sender Authenticity]        [Plaintext Bytes]
           │                                                         │
           └────────────────────────────┬────────────────────────────┘
                                        │
                                        ▼
                           [Recompute SHA-256 Hash]
                                        │
                                        ▼
                        [Compare with Expected Hash]
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
                 [Match: 100%]                  [Mismatch / Corrupt]
                 (Allow Download)               (Block & Raise Alert)
```

---

## 🔬 Core Security Primitives & Algorithms

| Primitive | Algorithm & Parameters | Purpose & Security Guarantee |
| :--- | :--- | :--- |
| **Bulk Encryption** | **AES-256-GCM** (Galois/Counter Mode) | Encrypts actual file payload. Uses 32-byte key, 12-byte random nonce, and produces a 16-byte (128-bit) GHASH authentication tag (AEAD). |
| **Key Encapsulation** | **RSA-2048 OAEP** (SHA-256 + MGF1) | Encrypts the 32-byte AES key with receiver's public key. OAEP padding prevents chosen-ciphertext attacks (CCA). |
| **Integrity Digest** | **SHA-256** (Secure Hash Algorithm 256) | Generates a 256-bit cryptographic fingerprint of the original file. Recomputed post-decryption. |
| **Digital Signature** | **RSA-PSS** (SHA-256 + Salt) | Sender signs canonical metadata with their RSA private key. Guarantees authenticity & non-repudiation. |
| **Password Protection**| **PBKDF2-HMAC-SHA256** | Salting and iterative key stretching for user passwords and private key protection at rest. |

---

## ⚙️ Sender & Receiver Workflows

### Sender Workflow (e.g., Alice)
1. Alice logs in to her dashboard.
2. Selects the recipient (Bob) from the registered directory.
3. Selects the file (PDF, text, images, docs) to upload.
4. The system calculates the **SHA-256** digest of the original file in memory.
5. Generates a fresh **256-bit random AES key** and a **96-bit random nonce**.
6. Encrypts file bytes with **AES-256-GCM**, generating the ciphertext and a 128-bit authentication tag.
7. Encrypts the AES key using **Bob's RSA-2048 public key** with **OAEP (SHA-256)** padding.
8. Signs the canonical package metadata (`hash + filename + sender_id + receiver_id`) using **Alice's RSA private key** with **RSA-PSS**.
9. Saves only the encrypted ciphertext (`<uuid>.enc`) to disk. **Plaintext is NEVER stored on the server disk.**
10. Records the cryptographic metadata in the SQLite database.

### Receiver Workflow (e.g., Bob)
1. Bob logs in to his account.
2. Navigates to the **Received Files** page.
3. Selects the incoming encrypted file package and clicks **Verify & Decrypt**.
4. Decrypts the encapsulated AES key using **Bob's RSA private key** (OAEP).
5. Reads the stored ciphertext and decrypts it using **AES-256-GCM** with the recovered key, nonce, and authentication tag.
6. Cryptographically verifies Alice's digital signature using **Alice's RSA public key** (RSA-PSS).
7. Recomputes the **SHA-256** digest over the decrypted plaintext and compares it against Alice's certified hash.
8. If all 4 checks pass, renders a green verification audit screen and unlocks the **Download Verified File** button.

---

## 📁 Project Directory Structure

```text
cns/
├── app.py                     # Main Flask routes & controller logic
├── config.py                  # Storage directories, database path & settings
├── requirements.txt           # Project Python dependencies
├── README.md                  # Complete documentation and viva guide
├── .env.example               # Template environment configuration
├── .gitignore                 # Files excluded from git
│
├── crypto/                    # Pure cryptographic modules
│   ├── __init__.py
│   ├── aes.py                 # AES-256-GCM encryption & decryption
│   ├── rsa.py                 # RSA-2048 keypair generation & OAEP wrapping
│   ├── hashing.py             # SHA-256 hashing & constant-time verification
│   └── signatures.py          # RSA-PSS digital signatures & verification
│
├── models/
│   ├── database.py            # SQLite schema, queries, and repositories
│   └── secure_share.db        # SQLite database file
│
├── templates/                 # Jinja2 HTML templates
│   ├── base.html              # Core layout, security ribbon, navbar, footer
│   ├── index.html             # Landing page with architecture cards
│   ├── register.html          # Registration & live RSA key generation
│   ├── login.html             # User login
│   ├── dashboard.html         # User dashboard & security specs banner
│   ├── upload.html            # Send file page with dropzone & explanation
│   ├── sent_files.html        # Outbound file history
│   ├── received_files.html    # Inbound file packages
│   └── verification.html      # Centerpiece cryptographic audit inspection report
│
├── static/
│   ├── css/
│   │   └── style.css          # Responsive modern cyber-security design
│   └── js/
│       └── script.js          # Drag-and-drop, copy buttons, live alerts
│
├── storage/
│   ├── encrypted/             # Stores ONLY AES-encrypted ciphertexts (*.enc)
│   └── keys/                  # Exported public keys (*_public.pem)
│
└── tests/
    ├── test_crypto.py         # Unit tests for pure crypto primitives
    ├── test_e2e_flask.py      # Flask integration & negative security tests
    └── test_live_server.py    # HTTP socket test against running dev server
```

---

## 💻 Prerequisites & Installation

### 1. Requirements
- Python 3.10+ (Tested on Python 3.14)
- Pip package manager

### 2. Clone / Open Project
```bash
cd c:\Users\aarti\OneDrive\cns
```

### 3. Install Dependencies
```bash
python -m pip install -r requirements.txt
```
Installed packages:
- `Flask>=3.0.0` (Web framework)
- `cryptography>=42.0.0` (Standard Python cryptography library)
- `Werkzeug>=3.0.0` (WSGI utilities & password hashing)

---

## 🚀 Running the Application

### 1. Start the Flask Server
```bash
python app.py
```
Output:
```text
=============================================================
 Secure File Sharing System Using Hybrid Cryptography
 AES-256-GCM | RSA-2048 | SHA-256 | RSA-PSS
 Running at: http://127.0.0.1:5000
=============================================================
```

### 2. Access the Application
Open your web browser and navigate to:
```
http://127.0.0.1:5000
```

### 3. Step-by-Step Demonstration (Alice & Bob)
1. **Register User 1:**
   - Go to Register.
   - Username: `alice`, Email: `alice@college.edu`, Password: `AlicePassword123!`.
   - Click *Generate Keys & Register*.
2. **Register User 2:**
   - Go to Register.
   - Username: `bob`, Email: `bob@college.edu`, Password: `BobPassword456!`.
3. **Login as Alice:**
   - Username: `alice`, Password: `AlicePassword123!`.
   - Navigate to **Send File**.
   - Select recipient: `bob`.
   - Select any sample file (PDF, TXT, PNG, etc.).
   - Click **Encrypt, Sign & Send File**.
4. **Logout and Login as Bob:**
   - Click Logout.
   - Login as `bob` with `BobPassword456!`.
   - Go to **Received Files**.
   - Click **🔍 Verify & Decrypt**.
   - Observe the 4-layer cryptographic audit breakdown:
     - 1. RSA-2048 OAEP Decapsulation: `DECAPSULATED`
     - 2. AES-256-GCM AEAD Tag: `TAG VERIFIED`
     - 3. RSA-PSS Digital Signature: `SIGNATURE VALID`
     - 4. SHA-256 Integrity: `MATCH 100%`
   - Click **⬇️ Download Verified File** to receive the authentic decrypted file.

---

## 🧪 Testing & Security Proofs

This project contains automated unit, integration, and live network tests.

### Run All Test Suites
```bash
python -m unittest discover tests
```
Output:
```text
........
----------------------------------------------------------------------
Ran 8 tests in 1.664s

OK
```

### Key Tests Implemented:
1. **`test_aes_gcm_tamper_detection`:** Flips 1 bit in ciphertext and verifies that AES-GCM immediately raises an error and rejects decryption.
2. **`test_rsa_oaep_key_encapsulation`:** Verifies 256-bit AES key wrapping and recovery using 2048-bit RSA keys.
3. **`test_rsa_pss_digital_signature`:** Confirms signatures verify correctly, and tampered message payloads are rejected.
4. **`test_01_complete_lifecycle_and_negative_security_checks`:** Simulates end-to-end user actions and confirms an unauthorized third user (Eve) is denied access.
5. **`test_02_tamper_detection_on_ciphertext`:** Corrupts the physical file on disk and verifies the web application displays tamper warnings and blocks download.

---

## 🎓 CNS Mini Project Viva Q&A Guide

**Q1: What is Hybrid Cryptography and why is it used?**
> *Answer:* Hybrid Cryptography combines the strengths of symmetric encryption (fast performance on large files) and asymmetric encryption (convenient and secure key exchange). Symmetric ciphers encrypt the file data, while asymmetric ciphers securely transmit the symmetric key.

**Q2: Why use AES in GCM (Galois/Counter Mode) rather than CBC or ECB?**
> *Answer:* ECB mode leaks pattern information because identical plaintext blocks produce identical ciphertext blocks. CBC mode requires padding and is susceptible to padding oracle attacks. GCM is an **AEAD (Authenticated Encryption with Associated Data)** mode that provides both confidentiality and built-in authenticity via a 128-bit GHASH authentication tag, eliminating the need for a separate HMAC.

**Q3: What is the purpose of the 96-bit Nonce in AES-GCM?**
> *Answer:* A Nonce (Number used Once) ensures that encrypting the same file twice produces completely different ciphertexts. In GCM, reusing a nonce with the same key catastrophically breaks security. Our system generates a cryptographically fresh 96-bit random nonce for every file using `os.urandom(12)`.

**Q4: Why use RSA-OAEP instead of PKCS#1 v1.5 padding?**
> *Answer:* PKCS#1 v1.5 is deterministic and vulnerable to Bleichenbacher's million-message chosen-ciphertext attack. OAEP (Optimal Asymmetric Encryption Padding) incorporates random salting, a mask generation function (MGF1), and SHA-256 hashing to achieve semantic security (indistinguishability under adaptive chosen ciphertext attacks - IND-CCA2).

**Q5: Why use RSA-PSS for digital signatures?**
> *Answer:* RSA-PSS (Probabilistic Signature Scheme) is mathematically proven to be secure based on the hardness of the RSA problem. Unlike deterministic schemes, PSS adds a randomized salt to each signature, preventing signature forgery and replay attacks.

**Q6: Are plaintext files stored on the server?**
> *Answer:* No. Plaintext files are read in memory, encrypted immediately into AES-256-GCM ciphertext, and written to `storage/encrypted/<uuid>.enc`. Only ciphertexts exist at rest.

---

## 🔮 Future Scope
- Integration with Multi-Factor Authentication (TOTP / Google Authenticator).
- Multi-party file sharing (encrypting symmetric key for multiple recipients using their respective public keys).
- Certificate Authority (X.509 certificates) integration to prevent Public Key Infrastructure (PKI) spoofing.
- Elliptic Curve Cryptography (ECC) support (e.g., ECDSA / X25519) for smaller key sizes and higher performance.
