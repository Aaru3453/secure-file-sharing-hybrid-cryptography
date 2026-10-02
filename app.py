"""
Secure File Sharing System Using Hybrid Cryptography
====================================================
Main Flask Application

Algorithms Implemented:
1. AES-256-GCM: Symmetric file encryption with authenticated data & integrity tag.
2. RSA-2048 OAEP: Asymmetric key encapsulation for symmetric AES key transfer.
3. SHA-256: Cryptographic file digest for tamper detection.
4. RSA-PSS SHA-256: Digital signature for authenticity and non-repudiation.
"""

import os
import uuid
import base64
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, 
    flash, session, send_file, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import io

from config import Config
from models.database import (
    init_db, create_user, get_user_by_username, get_user_by_id,
    get_all_other_users, insert_file_record, get_sent_files,
    get_received_files, get_file_by_id, update_file_status, get_user_stats
)
from crypto.aes import generate_aes_key, encrypt_file, decrypt_file
from crypto.rsa import generate_rsa_keypair, encrypt_aes_key, decrypt_aes_key
from crypto.hashing import calculate_sha256, verify_sha256
from crypto.signatures import create_signature, verify_signature, build_signature_payload

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize storage directories and database
Config.init_app()
init_db(app.config['DATABASE'])


def login_required(f):
    """Decorator to require user login for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    """Check if uploaded file has an allowed extension."""
    if '.' not in filename:
        return True  # Allow files without extension as raw binary
    return filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


@app.context_processor
def inject_user():
    """Inject current logged-in user information into all templates."""
    current_user = None
    if 'user_id' in session:
        current_user = get_user_by_id(app.config['DATABASE'], session['user_id'])
    return dict(current_user=current_user)


# ==========================================
# PUBLIC ROUTES
# ==========================================

@app.route('/')
def index():
    """Landing page introducing the Hybrid Cryptography architecture."""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration and RSA-2048 key pair generation."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Basic input validation
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('register.html')
            
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template('register.html')
            
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html')

        # Check existing user
        existing_user = get_user_by_username(app.config['DATABASE'], username)
        if existing_user:
            flash("Username is already taken. Please choose another.", "danger")
            return render_template('register.html')

        try:
            # 1. Generate RSA-2048 key pair (private key encrypted with user password)
            private_key_pem, public_key_pem = generate_rsa_keypair(password=password)
            
            # 2. Hash password with secure Werkzeug method (PBKDF2-HMAC-SHA256)
            password_hash = generate_password_hash(password)

            # 3. Store user in SQLite database
            user_id = create_user(
                app.config['DATABASE'],
                username=username,
                email=email,
                password_hash=password_hash,
                public_key_pem=public_key_pem,
                private_key_pem=private_key_pem
            )
            
            # 4. Save public key PEM to storage/keys/ for public inspection / verification
            pub_key_path = os.path.join(Config.KEYS_DIR, f"{username}_public.pem")
            with open(pub_key_path, 'w', encoding='utf-8') as f:
                f.write(public_key_pem)

            flash("Registration successful! Your 2048-bit RSA key pair has been generated.", "success")
            return redirect(url_for('login'))
            
        except Exception as e:
            flash(f"Error during registration: {str(e)}", "danger")
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User authentication."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = get_user_by_username(app.config['DATABASE'], username)
        if user and check_password_hash(user['password_hash'], password):
            # Session setup
            session['user_id'] = user['id']
            session['username'] = user['username']
            # Store password in session to decrypt user's RSA private key during session actions
            session['user_password'] = password
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clear session and log out."""
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('login'))


# ==========================================
# AUTHENTICATED USER ROUTES
# ==========================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing cryptographic statistics and security specs."""
    user = get_user_by_id(app.config['DATABASE'], session['user_id'])
    stats = get_user_stats(app.config['DATABASE'], session['user_id'])
    sent_recent = get_sent_files(app.config['DATABASE'], session['user_id'])[:5]
    received_recent = get_received_files(app.config['DATABASE'], session['user_id'])[:5]
    
    # Calculate public key fingerprint (SHA-256 of public key PEM)
    key_fingerprint = calculate_sha256(user['public_key_pem'].encode('utf-8'))

    return render_template(
        'dashboard.html',
        user=user,
        stats=stats,
        sent_recent=sent_recent,
        received_recent=received_recent,
        key_fingerprint=key_fingerprint
    )


@app.route('/send', methods=['GET', 'POST'])
@login_required
def send_file_page():
    """
    Sender Workflow:
    1. Select receiver and file.
    2. Compute SHA-256 of plaintext file.
    3. Generate fresh 256-bit AES key & 96-bit nonce.
    4. Encrypt file with AES-256-GCM (producing ciphertext + 128-bit auth tag).
    5. Encapsulate AES key using Receiver's RSA-2048 Public Key (OAEP SHA-256).
    6. Sign canonical package payload using Sender's RSA-2048 Private Key (RSA-PSS SHA-256).
    7. Store encrypted ciphertext in storage/encrypted/<uuid>.enc (NO plaintext saved).
    8. Store cryptographic package metadata in database.
    """
    other_users = get_all_other_users(app.config['DATABASE'], session['user_id'])

    if request.method == 'POST':
        receiver_id = request.form.get('receiver_id')
        file_obj = request.files.get('file')

        if not receiver_id:
            flash("Please select a valid recipient.", "danger")
            return render_template('upload.html', other_users=other_users)

        if not file_obj or file_obj.filename == '':
            flash("Please choose a file to encrypt and send.", "danger")
            return render_template('upload.html', other_users=other_users)

        original_filename = secure_filename(file_obj.filename)
        if not original_filename:
            original_filename = "shared_file.bin"

        receiver = get_user_by_id(app.config['DATABASE'], int(receiver_id))
        if not receiver:
            flash("Recipient not found.", "danger")
            return render_template('upload.html', other_users=other_users)

        sender = get_user_by_id(app.config['DATABASE'], session['user_id'])

        try:
            # Read plaintext bytes in memory
            plaintext_bytes = file_obj.read()
            file_size = len(plaintext_bytes)

            if file_size == 0:
                flash("Cannot send an empty file.", "danger")
                return render_template('upload.html', other_users=other_users)

            # Step 1: Calculate SHA-256 hash of original file
            original_sha256 = calculate_sha256(plaintext_bytes)

            # Step 2: Generate random 256-bit AES key
            aes_key = generate_aes_key()

            # Step 3: Encrypt file with AES-256-GCM
            nonce, ciphertext, auth_tag = encrypt_file(plaintext_bytes, aes_key)

            # Step 4: Encrypt AES key with Receiver's RSA-2048 public key via OAEP
            encrypted_aes_key = encrypt_aes_key(aes_key, receiver['public_key_pem'])

            # Step 5: Digitally sign package metadata with Sender's RSA-2048 private key via RSA-PSS
            sig_payload = build_signature_payload(
                original_sha256=original_sha256,
                original_filename=original_filename,
                sender_id=sender['id'],
                receiver_id=receiver['id']
            )
            digital_signature = create_signature(
                sig_payload,
                sender['private_key_pem'],
                session.get('user_password')
            )

            # Step 6: Store encrypted ciphertext file on disk (never store plaintext!)
            stored_filename = f"{uuid.uuid4().hex}.enc"
            encrypted_file_path = os.path.join(Config.ENCRYPTED_DIR, stored_filename)
            with open(encrypted_file_path, 'wb') as f:
                f.write(ciphertext)

            # Step 7: Record transfer package in database
            insert_file_record(
                db_path=app.config['DATABASE'],
                sender_id=sender['id'],
                receiver_id=receiver['id'],
                original_filename=original_filename,
                stored_filename=stored_filename,
                file_size=file_size,
                encrypted_aes_key=encrypted_aes_key,
                nonce=nonce,
                auth_tag=auth_tag,
                original_sha256=original_sha256,
                digital_signature=digital_signature
            )

            flash(f"File '{original_filename}' encrypted and securely transferred to {receiver['username']}!", "success")
            return redirect(url_for('sent_files_page'))

        except Exception as e:
            flash(f"Encryption and transfer failed: {str(e)}", "danger")
            return render_template('upload.html', other_users=other_users)

    return render_template('upload.html', other_users=other_users)


@app.route('/sent-files')
@login_required
def sent_files_page():
    """Display history of files sent by the current user."""
    files = get_sent_files(app.config['DATABASE'], session['user_id'])
    return render_template('sent_files.html', files=files)


@app.route('/received-files')
@login_required
def received_files_page():
    """Display history of files received by the current user."""
    files = get_received_files(app.config['DATABASE'], session['user_id'])
    return render_template('received_files.html', files=files)


@app.route('/verify/<int:file_id>')
@login_required
def verify_and_decrypt_page(file_id):
    """
    Receiver Workflow & Technical Cryptographic Audit:
    1. Retrieve encrypted package.
    2. Decrypt AES key with Receiver's RSA private key (RSA-OAEP).
    3. Decrypt ciphertext using recovered AES key & Nonce & Auth Tag (AES-256-GCM).
    4. Verify Sender's RSA-PSS Digital Signature using Sender's public key.
    5. Recompute SHA-256 of decrypted plaintext and compare with original_sha256.
    6. Render full inspection report for CNS mini project demonstration.
    """
    file_record = get_file_by_id(app.config['DATABASE'], file_id)

    if not file_record:
        flash("File record not found.", "danger")
        return redirect(url_for('received_files_page'))

    # Security check: only the intended receiver can decrypt
    if file_record['receiver_id'] != session['user_id']:
        flash("Access Denied: You are not the designated recipient of this encrypted file.", "danger")
        return redirect(url_for('dashboard'))

    receiver = get_user_by_id(app.config['DATABASE'], session['user_id'])
    sender = get_user_by_id(app.config['DATABASE'], file_record['sender_id'])

    # Prepare audit metrics
    verification_results = {
        'rsa_oaep_decapsulation': False,
        'aes_gcm_decryption': False,
        'aes_gcm_tag_valid': False,
        'digital_signature_valid': False,
        'sha256_integrity_match': False,
        'original_hash': file_record['original_sha256'],
        'recomputed_hash': None,
        'signature_hex': file_record['digital_signature'].hex()[:64] + "...",
        'nonce_hex': file_record['nonce'].hex(),
        'auth_tag_hex': file_record['auth_tag'].hex(),
        'encrypted_aes_key_hex': file_record['encrypted_aes_key'].hex()[:64] + "...",
        'error_message': None
    }

    try:
        # Step 1: RSA-OAEP Decrypt AES Key using Receiver's private key
        user_password = session.get('user_password')
        aes_key = decrypt_aes_key(
            file_record['encrypted_aes_key'],
            receiver['private_key_pem'],
            user_password
        )
        verification_results['rsa_oaep_decapsulation'] = True

        # Step 2: Read stored ciphertext from encrypted folder
        encrypted_path = os.path.join(Config.ENCRYPTED_DIR, file_record['stored_filename'])
        if not os.path.exists(encrypted_path):
            raise FileNotFoundError("Ciphertext file missing from encrypted storage.")

        with open(encrypted_path, 'rb') as f:
            ciphertext = f.read()

        # Step 3: Decrypt using AES-256-GCM
        decrypted_bytes = decrypt_file(
            file_record['nonce'],
            ciphertext,
            file_record['auth_tag'],
            aes_key
        )
        verification_results['aes_gcm_decryption'] = True
        verification_results['aes_gcm_tag_valid'] = True

        # Step 4: Verify Digital Signature using Sender's Public Key (RSA-PSS)
        sig_payload = build_signature_payload(
            original_sha256=file_record['original_sha256'],
            original_filename=file_record['original_filename'],
            sender_id=file_record['sender_id'],
            receiver_id=file_record['receiver_id']
        )
        is_sig_valid = verify_signature(
            sig_payload,
            file_record['digital_signature'],
            sender['public_key_pem']
        )
        verification_results['digital_signature_valid'] = is_sig_valid

        # Step 5: Recompute SHA-256 integrity hash
        recomputed_hash = calculate_sha256(decrypted_bytes)
        verification_results['recomputed_hash'] = recomputed_hash
        
        is_hash_match = verify_sha256(decrypted_bytes, file_record['original_sha256'])
        verification_results['sha256_integrity_match'] = is_hash_match

        # If everything passes, update status to 'verified'
        if is_sig_valid and is_hash_match:
            update_file_status(app.config['DATABASE'], file_id, 'verified')

    except Exception as e:
        verification_results['error_message'] = str(e)

    return render_template(
        'verification.html',
        file=file_record,
        sender=sender,
        receiver=receiver,
        audit=verification_results
    )


@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    """
    Download route: Decrypts and serves original plaintext file only if verification passes.
    """
    file_record = get_file_by_id(app.config['DATABASE'], file_id)
    if not file_record:
        flash("File record not found.", "danger")
        return redirect(url_for('received_files_page'))

    if file_record['receiver_id'] != session['user_id']:
        flash("Unauthorized download attempt.", "danger")
        return redirect(url_for('dashboard'))

    receiver = get_user_by_id(app.config['DATABASE'], session['user_id'])
    sender = get_user_by_id(app.config['DATABASE'], file_record['sender_id'])

    try:
        # Decrypt AES key with Receiver's private key
        aes_key = decrypt_aes_key(
            file_record['encrypted_aes_key'],
            receiver['private_key_pem'],
            session.get('user_password')
        )

        # Read encrypted ciphertext
        encrypted_path = os.path.join(Config.ENCRYPTED_DIR, file_record['stored_filename'])
        with open(encrypted_path, 'rb') as f:
            ciphertext = f.read()

        # Decrypt with AES-256-GCM
        plaintext_bytes = decrypt_file(
            file_record['nonce'],
            ciphertext,
            file_record['auth_tag'],
            aes_key
        )

        # Integrity check
        if not verify_sha256(plaintext_bytes, file_record['original_sha256']):
            flash("Integrity check failed: Plaintext hash does not match original file hash!", "danger")
            return redirect(url_for('verify_and_decrypt_page', file_id=file_id))

        # Digital signature check
        sig_payload = build_signature_payload(
            original_sha256=file_record['original_sha256'],
            original_filename=file_record['original_filename'],
            sender_id=file_record['sender_id'],
            receiver_id=file_record['receiver_id']
        )
        if not verify_signature(sig_payload, file_record['digital_signature'], sender['public_key_pem']):
            flash("Digital signature invalid: Sender identity could not be verified!", "danger")
            return redirect(url_for('verify_and_decrypt_page', file_id=file_id))

        # Update status
        update_file_status(app.config['DATABASE'], file_id, 'downloaded')

        # Send file directly from memory as an attachment
        return send_file(
            io.BytesIO(plaintext_bytes),
            as_attachment=True,
            download_name=file_record['original_filename']
        )

    except Exception as e:
        flash(f"Decryption or download error: {str(e)}", "danger")
        return redirect(url_for('verify_and_decrypt_page', file_id=file_id))


@app.route('/download-public-key/<username>')
def download_public_key(username):
    """Download a user's public key in PEM format."""
    user = get_user_by_username(app.config['DATABASE'], username)
    if not user:
        abort(404)
    return send_file(
        io.BytesIO(user['public_key_pem'].encode('utf-8')),
        as_attachment=True,
        download_name=f"{username}_rsa2048_public.pem",
        mimetype="application/x-pem-file"
    )


if __name__ == '__main__':
    print("=============================================================")
    print(" Secure File Sharing System Using Hybrid Cryptography")
    print(" AES-256-GCM | RSA-2048 | SHA-256 | RSA-PSS")
    print(" Running at: http://127.0.0.1:5000")
    print("=============================================================")
    app.run(debug=True, host='127.0.0.1', port=5000)
