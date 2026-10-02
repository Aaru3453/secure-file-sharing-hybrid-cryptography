import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Application configuration for Secure File Sharing System."""
    BASE_DIR = BASE_DIR
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cns-hybrid-crypto-super-secret-key-2026')
    DATABASE = os.path.join(BASE_DIR, 'models', 'secure_share.db')
    
    # Storage folders
    STORAGE_DIR = os.path.join(BASE_DIR, 'storage')
    ENCRYPTED_DIR = os.path.join(STORAGE_DIR, 'encrypted')
    KEYS_DIR = os.path.join(STORAGE_DIR, 'keys')
    
    # Upload constraints
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max file size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'xlsx', 'zip', 'csv', 'py', 'json', 'c', 'cpp'}

    @classmethod
    def init_app(cls):
        """Ensure necessary storage directories exist."""
        os.makedirs(cls.ENCRYPTED_DIR, exist_ok=True)
        os.makedirs(cls.KEYS_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(cls.DATABASE), exist_ok=True)
