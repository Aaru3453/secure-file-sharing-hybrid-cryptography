"""
RSA-2048 Module with OAEP Padding
=================================
Implements asymmetric cryptography for key encapsulation (wrapping the symmetric AES key).
- Key Size: 2048 bits
- Public Exponent (e): 65537 (Fermat Prime F4)
- Padding Scheme: OAEP (Optimal Asymmetric Encryption Padding) with MGF1 and SHA-256 hash.
  OAEP prevents chosen-ciphertext attacks (CCA) and padding oracle attacks.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_rsa_keypair(password: str = None) -> tuple[str, str]:
    """
    Generate an RSA-2048 key pair.
    
    Parameters:
        password (str, optional): User's password to encrypt the private key PEM.
                                 If None, private key is serialized unencrypted.
                                 
    Returns:
        tuple (private_key_pem, public_key_pem): Both encoded as UTF-8 strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    encryption_algorithm = (
        serialization.BestAvailableEncryption(password.encode('utf-8'))
        if password
        else serialization.NoEncryption()
    )
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    ).decode('utf-8')
    
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key_pem, public_key_pem


def load_private_key(private_key_pem: str, password: str = None):
    """
    Deserialize a PEM-encoded RSA private key.
    """
    password_bytes = password.encode('utf-8') if password else None
    return serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=password_bytes
    )


def load_public_key(public_key_pem: str):
    """
    Deserialize a PEM-encoded RSA public key.
    """
    return serialization.load_pem_public_key(
        public_key_pem.encode('utf-8')
    )


def encrypt_aes_key(aes_key: bytes, receiver_public_key_pem: str) -> bytes:
    """
    Encrypt the 256-bit AES symmetric key using the Receiver's RSA-2048 Public Key
    with OAEP padding and SHA-256.
    
    Parameters:
        aes_key (bytes): The 32-byte AES key.
        receiver_public_key_pem (str): Receiver's public key in PEM format.
        
    Returns:
        bytes: Encrypted AES key (256 bytes = 2048 bits).
    """
    public_key = load_public_key(receiver_public_key_pem)
    
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_aes_key(encrypted_aes_key: bytes, receiver_private_key_pem: str, password: str = None) -> bytes:
    """
    Decrypt the encapsulated AES key using the Receiver's RSA-2048 Private Key.
    
    Parameters:
        encrypted_aes_key (bytes): Encrypted 256-byte ciphertext of the AES key.
        receiver_private_key_pem (str): Receiver's private key PEM.
        password (str, optional): Password to decrypt the private key if protected.
        
    Returns:
        bytes: The recovered 32-byte AES key.
    """
    private_key = load_private_key(receiver_private_key_pem, password)
    
    decrypted_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key
