"""
AEGIS-Social Security, Cryptography & Privacy Protection Engine
Handles password hashing, token validation, tamper-evident signing, and privacy anonymization.
"""
import os
import hashlib
import hmac
import secrets
import base64
import time
from datetime import datetime
from backend.config import SECRET_KEY, PASSWORD_SALT_BYTES, PBKDF2_ITERATIONS


def hash_password(password: str) -> str:
    """Generate salted PBKDF2-HMAC-SHA256 password hash."""
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        PBKDF2_ITERATIONS
    )
    # Format: salt_hex$key_hex
    return f"{salt.hex()}${key.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Safely verify password against stored salted PBKDF2 hash using constant-time comparison."""
    try:
        salt_hex, key_hex = stored_hash.split('$')
        salt = bytes.fromhex(salt_hex)
        expected_key = bytes.fromhex(key_hex)
        candidate_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(candidate_key, expected_key)
    except Exception:
        return False


def generate_session_token() -> str:
    """Generate cryptographically secure 256-bit URL-safe session token."""
    return secrets.token_urlsafe(32)


def generate_otp() -> str:
    """Generate cryptographically secure 6-digit numeric One-Time Password (OTP)."""
    return f"{secrets.randbelow(900000) + 100000}"



def compute_file_sha256(file_path: str) -> str:
    """Compute cryptographic SHA-256 digest of a file for tamper evidence."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of byte array."""
    return hashlib.sha256(data).hexdigest()


def sign_evidence_record(record_payload: str) -> str:
    """
    Produce tamper-evident HMAC-SHA256 signature for evidence vault preservation.
    Complies with legal audit trails (Indian IT Act 65B / Federal Rules of Evidence 902(11)).
    """
    sig = hmac.new(SECRET_KEY.encode('utf-8'), record_payload.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"AEGIS-SIG-{sig[:32].upper()}"


def anonymize_handle(handle: str) -> str:
    """Partially mask usernames for privacy in public displays."""
    if not handle:
        return ""
    if len(handle) <= 4:
        return handle[0] + "***"
    return handle[:2] + "***" + handle[-2:]
