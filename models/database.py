"""
Database Models & SQLite Helper Operations
===========================================
Manages users, RSA key storage, and encrypted file transfer records.
"""

import sqlite3
from datetime import datetime


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Get a SQLite database connection with row factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str):
    """Initialize database tables for users and shared files."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        original_filename TEXT NOT NULL,
        stored_filename TEXT NOT NULL,
        file_size INTEGER NOT NULL,
        encrypted_aes_key BLOB NOT NULL,
        nonce BLOB NOT NULL,
        auth_tag BLOB NOT NULL,
        original_sha256 TEXT NOT NULL,
        digital_signature BLOB NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        status TEXT DEFAULT 'pending_verification',
        FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)
    
    conn.commit()
    conn.close()


def create_user(db_path: str, username: str, email: str, password_hash: str, 
                public_key_pem: str, private_key_pem: str) -> int:
    """Insert a newly registered user with their RSA key pair."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, public_key_pem, private_key_pem)
        VALUES (?, ?, ?, ?, ?)
    """, (username, email, password_hash, public_key_pem, private_key_pem))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return user_id


def get_user_by_username(db_path: str, username: str):
    """Retrieve user record by username."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_user_by_id(db_path: str, user_id: int):
    """Retrieve user record by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_all_other_users(db_path: str, current_user_id: int):
    """Get list of all users other than the current user for receiver selection."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email FROM users WHERE id != ? ORDER BY username ASC", 
        (current_user_id,)
    )
    users = cursor.fetchall()
    conn.close()
    return users


def insert_file_record(db_path: str, sender_id: int, receiver_id: int, 
                       original_filename: str, stored_filename: str, file_size: int, 
                       encrypted_aes_key: bytes, nonce: bytes, auth_tag: bytes, 
                       original_sha256: str, digital_signature: bytes) -> int:
    """Record an encrypted file package transfer in the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO files (
            sender_id, receiver_id, original_filename, stored_filename, file_size,
            encrypted_aes_key, nonce, auth_tag, original_sha256, digital_signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        sender_id, receiver_id, original_filename, stored_filename, file_size,
        encrypted_aes_key, nonce, auth_tag, original_sha256, digital_signature
    ))
    file_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return file_id


def get_sent_files(db_path: str, sender_id: int):
    """Get history of files sent by user."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.*, u.username AS receiver_username, u.email AS receiver_email
        FROM files f
        JOIN users u ON f.receiver_id = u.id
        WHERE f.sender_id = ?
        ORDER BY f.uploaded_at DESC
    """, (sender_id,))
    files = cursor.fetchall()
    conn.close()
    return files


def get_received_files(db_path: str, receiver_id: int):
    """Get history of files received by user."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.*, u.username AS sender_username, u.email AS sender_email, u.public_key_pem AS sender_public_key
        FROM files f
        JOIN users u ON f.sender_id = u.id
        WHERE f.receiver_id = ?
        ORDER BY f.uploaded_at DESC
    """, (receiver_id,))
    files = cursor.fetchall()
    conn.close()
    return files


def get_file_by_id(db_path: str, file_id: int):
    """Get file record by ID with sender and receiver information."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT f.*, 
               sender.username AS sender_username, sender.email AS sender_email, sender.public_key_pem AS sender_public_key,
               receiver.username AS receiver_username, receiver.email AS receiver_email
        FROM files f
        JOIN users sender ON f.sender_id = sender.id
        JOIN users receiver ON f.receiver_id = receiver.id
        WHERE f.id = ?
    """, (file_id,))
    file_record = cursor.fetchone()
    conn.close()
    return file_record


def update_file_status(db_path: str, file_id: int, status: str):
    """Update verification / download status of a file."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE files SET status = ? WHERE id = ?", (status, file_id))
    conn.commit()
    conn.close()


def get_user_stats(db_path: str, user_id: int):
    """Return count of sent and received files for dashboard."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM files WHERE sender_id = ?", (user_id,))
    sent_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM files WHERE receiver_id = ?", (user_id,))
    received_count = cursor.fetchone()[0]
    conn.close()
    return {"sent_count": sent_count, "received_count": received_count}
