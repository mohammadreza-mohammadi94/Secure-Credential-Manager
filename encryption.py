# encryption.py

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a secure encryption key from a user's password and a salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_text(text: str, key: bytes) -> str:
    """Encrypt text using a derived Fernet key."""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode('utf-8'))
    return base64.urlsafe_b64encode(encrypted).decode('utf-8')

def decrypt_text(encrypted_text: str, key: bytes) -> str:
    """Decrypt text using a derived Fernet key."""
    try:
        fernet = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
        decrypted = fernet.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return "Decryption Failed"

# --- Wrapper Functions ---

def secure_store(text: str, key: bytes) -> str:
    """Encrypt and store text securely."""
    if not text:
        return ""
    return encrypt_text(text, key)

def retrieve_secure(encrypted_text: str, key: bytes) -> str:
    """Decrypt and retrieve text."""
    if not encrypted_text:
        return ""
    return decrypt_text(encrypted_text, key)