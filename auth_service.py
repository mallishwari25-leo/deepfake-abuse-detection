"""
AEGIS-Social Authentication & Profile Service
Handles secure registration, consent recording, profile settings, and GDPR/DPDPA data purging.
"""
from datetime import datetime
import time
from typing import Optional, Dict, Any
from backend.database import get_db, log_audit_event
from backend.security import hash_password, verify_password, generate_session_token, generate_otp
from backend.config import CONSENT_VERSION, UPLOADS_DIR, EVIDENCE_DIR
import shutil
import os

# Thread-safe in-memory cache for active 2FA OTPs: {user_id: {"otp": str, "expires_at": float, "attempts": int}}
_ACTIVE_OTPS: Dict[int, Dict[str, Any]] = {}
# Active password reset OTPs: {user_id: {"otp": str, "expires_at": float, "attempts": int}}
_ACTIVE_RESET_OTPS: Dict[int, Dict[str, Any]] = {}


class AuthService:
    """Manages user identity, privacy consent, and profile security."""

    @classmethod
    def register_user(
        cls,
        username: str,
        email: str,
        password: str,
        full_name: str,
        consent_given: bool = False,
        country: str = "India",
        emergency_contact_name: str = "",
        emergency_contact_phone: str = "",
        emergency_contact_email: str = ""
    ) -> Dict[str, Any]:
        """Register a new user account with cryptographic password hashing."""
        if not username or not email or not password:
            return {"success": False, "error": "Username, email, and password are required."}

        pwd_hash = hash_password(password)
        now = datetime.now().isoformat()
        consent_int = 1 if consent_given else 0

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO users (
                    username, email, password_hash, full_name, created_at,
                    consent_given, consent_timestamp, country,
                    emergency_contact_name, emergency_contact_phone, emergency_contact_email
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    username.strip().lower(),
                    email.strip().lower(),
                    pwd_hash,
                    full_name.strip(),
                    now,
                    consent_int,
                    now if consent_given else None,
                    country,
                    emergency_contact_name,
                    emergency_contact_phone,
                    emergency_contact_email
                ))
                user_id = cursor.lastrowid

            log_audit_event(user_id, "USER_REGISTERED", f"Account created with consent={consent_given}")
            user_profile = cls.get_user_by_id(user_id)
            return {"success": True, "user_id": user_id, "username": username, "user": user_profile}
        except Exception as e:
            if "UNIQUE constraint failed" in str(e):
                return {"success": False, "error": "Username or email is already registered."}
            return {"success": False, "error": str(e)}

    @classmethod
    def authenticate_user(cls, username: str, password: str) -> Dict[str, Any]:
        """Authenticate user credentials and return user profile."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (username.strip().lower(), username.strip().lower()))
            row = cursor.fetchone()

        if not row:
            return {"success": False, "error": "Invalid username or password."}

        if not verify_password(password, row["password_hash"]):
            return {"success": False, "error": "Invalid username or password."}

        user_data = dict(row)
        user_data.pop("password_hash", None)
        token = generate_session_token()
        user_data["session_token"] = token

        log_audit_event(user_data["id"], "USER_LOGIN", "Successful login authentication")
        return {"success": True, "user": user_data}

    @classmethod
    def initiate_2fa_login(cls, username: str, password: str) -> Dict[str, Any]:
        """
        Step 1 of 2FA Authentication:
        Verifies login credentials and generates a 6-digit OTP code for verification.
        """
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (username.strip().lower(), username.strip().lower()))
            row = cursor.fetchone()

        if not row or not verify_password(password, row["password_hash"]):
            return {"success": False, "error": "Invalid username or password."}

        user_id = row["id"]
        otp = generate_otp()
        _ACTIVE_OTPS[user_id] = {
            "otp": otp,
            "expires_at": time.time() + 300,  # 5 minutes validity
            "attempts": 0,
            "user_id": user_id
        }

        email = row["email"]
        phone = row["emergency_contact_phone"] or ""
        masked_email = email[:2] + "***@" + email.split("@")[-1] if "@" in email else "***"
        masked_phone = phone[:3] + "****" + phone[-2:] if len(phone) >= 6 else "registered phone"

        log_audit_event(user_id, "2FA_OTP_GENERATED", f"OTP dispatched to {masked_email}")

        return {
            "success": True,
            "require_otp": True,
            "user_id": user_id,
            "username": row["username"],
            "full_name": row["full_name"],
            "masked_email": masked_email,
            "masked_phone": masked_phone,
            "otp_code": otp  # Returned for instant demonstration / SMS simulation
        }

    @classmethod
    def resend_2fa_otp(cls, user_id: int) -> Dict[str, Any]:
        """Regenerate a fresh 6-digit OTP code for a user during 2FA."""
        user = cls.get_user_by_id(user_id)
        if not user:
            return {"success": False, "error": "User profile not found."}

        otp = generate_otp()
        _ACTIVE_OTPS[user_id] = {
            "otp": otp,
            "expires_at": time.time() + 300,
            "attempts": 0,
            "user_id": user_id
        }

        email = user["email"]
        phone = user.get("emergency_contact_phone") or ""
        masked_email = email[:2] + "***@" + email.split("@")[-1] if "@" in email else "***"
        masked_phone = phone[:3] + "****" + phone[-2:] if len(phone) >= 6 else "registered phone"

        log_audit_event(user_id, "2FA_OTP_REGENERATED", f"Fresh OTP dispatched to {masked_email}")

        return {
            "success": True,
            "require_otp": True,
            "user_id": user_id,
            "username": user["username"],
            "full_name": user["full_name"],
            "masked_email": masked_email,
            "masked_phone": masked_phone,
            "otp_code": otp
        }

    @classmethod
    def verify_otp_and_login(cls, user_id: int, otp_input: str) -> Dict[str, Any]:
        """
        Step 2 of 2FA Authentication:
        Validates the 6-digit OTP code and creates the active session.
        """
        record = _ACTIVE_OTPS.get(user_id)
        if not record:
            return {"success": False, "error": "No active OTP request found. Please login again."}

        if time.time() > record["expires_at"]:
            _ACTIVE_OTPS.pop(user_id, None)
            return {"success": False, "error": "OTP has expired. Please request a new code."}

        record["attempts"] += 1
        if record["attempts"] > 5:
            _ACTIVE_OTPS.pop(user_id, None)
            return {"success": False, "error": "Too many failed OTP attempts. Please login again."}

        if str(record["otp"]).strip() != str(otp_input).strip():
            return {"success": False, "error": f"Invalid OTP code. {5 - record['attempts']} attempts remaining."}

        # Verification successful!
        _ACTIVE_OTPS.pop(user_id, None)
        user = cls.get_user_by_id(user_id)
        token = generate_session_token()
        user["session_token"] = token

        log_audit_event(user_id, "2FA_LOGIN_SUCCESS", "Two-factor authentication verified successfully")
        return {"success": True, "authenticated": True, "user": user}

    @classmethod
    def request_password_reset(cls, username_or_email: str) -> Dict[str, Any]:
        """
        Generates and dispatches a 6-digit verification code to the user's registered contact
        when they request a password reset.
        """
        if not username_or_email or not username_or_email.strip():
            return {"success": False, "error": "Please provide your username or registered email."}

        target = username_or_email.strip().lower()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (target, target))
            row = cursor.fetchone()

        if not row:
            return {"success": False, "error": f"No account found matching '{username_or_email}'. Please verify and try again."}

        user_id = row["id"]
        otp = generate_otp()
        _ACTIVE_RESET_OTPS[user_id] = {
            "otp": otp,
            "expires_at": time.time() + 600,  # 10 minutes validity for password reset
            "attempts": 0,
            "user_id": user_id
        }

        email = row["email"]
        phone = row["emergency_contact_phone"] or ""
        masked_email = email[:2] + "***@" + email.split("@")[-1] if "@" in email else "***"
        masked_phone = phone[:3] + "****" + phone[-2:] if len(phone) >= 6 else "registered phone"

        log_audit_event(user_id, "PASSWORD_RESET_OTP_GENERATED", f"Password reset verification code dispatched to {masked_email}")

        return {
            "success": True,
            "user_id": user_id,
            "username": row["username"],
            "full_name": row["full_name"],
            "masked_email": masked_email,
            "masked_phone": masked_phone,
            "reset_code": otp,  # Dispatched code for simulated SMS / Email display
            "message": f"Verification code sent to {masked_email} and {masked_phone}."
        }

    @classmethod
    def verify_reset_otp_and_set_password(cls, user_id: int, otp_input: str, new_password: str) -> Dict[str, Any]:
        """
        Verifies the 6-digit password reset code and updates the user's password in the database.
        """
        if not new_password or len(new_password) < 6:
            return {"success": False, "error": "New password must be at least 6 characters in length."}

        record = _ACTIVE_RESET_OTPS.get(user_id)
        if not record:
            return {"success": False, "error": "No active password reset request found or code has expired. Please request a new code."}

        if time.time() > record["expires_at"]:
            _ACTIVE_RESET_OTPS.pop(user_id, None)
            return {"success": False, "error": "Verification code has expired. Please request a new code."}

        record["attempts"] += 1
        if record["attempts"] > 5:
            _ACTIVE_RESET_OTPS.pop(user_id, None)
            return {"success": False, "error": "Too many invalid code attempts. Please request a new verification code."}

        if str(record["otp"]).strip() != str(otp_input).strip():
            return {"success": False, "error": f"Invalid verification code. {5 - record['attempts']} attempts remaining."}

        # Verification successful: Update password in SQLite
        new_pwd_hash = hash_password(new_password)
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_pwd_hash, user_id))

        _ACTIVE_RESET_OTPS.pop(user_id, None)
        log_audit_event(user_id, "PASSWORD_RESET_SUCCESSFUL", "Password updated successfully via OTP verification")

        return {
            "success": True,
            "message": "Password reset successfully! You can now log in with your new password."
        }


    @classmethod
    def get_user_by_id(cls, user_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve user profile by ID without password hash."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()

        if row:
            data = dict(row)
            data.pop("password_hash", None)
            return data
        return None

    @classmethod
    def update_consent(cls, user_id: int, consent_given: bool) -> bool:
        """Update explicit user consent timestamp and status."""
        now = datetime.now().isoformat()
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET consent_given = ?, consent_timestamp = ? WHERE id = ?",
                (1 if consent_given else 0, now, user_id)
            )
        log_audit_event(user_id, "CONSENT_UPDATED", f"Consent set to {consent_given} under {CONSENT_VERSION}")
        return True

    @classmethod
    def update_privacy_settings(cls, user_id: int, zero_retention: bool, emergency_name: str, emergency_phone: str, emergency_email: str) -> bool:
        """Update user safety profile and privacy options."""
        with get_db() as conn:
            conn.execute("""
            UPDATE users SET
                zero_retention_enabled = ?,
                emergency_contact_name = ?,
                emergency_contact_phone = ?,
                emergency_contact_email = ?
            WHERE id = ?
            """, (1 if zero_retention else 0, emergency_name, emergency_phone, emergency_email, user_id))
        log_audit_event(user_id, "PRIVACY_SETTINGS_UPDATED", f"ZeroRetention={zero_retention}")
        return True

    @classmethod
    def connect_social_account(cls, user_id: int, platform: str, handle: str) -> Dict[str, Any]:
        """Authorize a public social media handle for monitoring."""
        now = datetime.now().isoformat()
        with get_db() as conn:
            cursor = conn.cursor()
            # Check existing
            cursor.execute("SELECT id FROM social_accounts WHERE user_id = ? AND platform = ? AND handle = ?", (user_id, platform, handle))
            existing = cursor.fetchone()
            if existing:
                return {"success": True, "id": existing["id"], "message": "Account already linked."}

            cursor.execute("""
            INSERT INTO social_accounts (user_id, platform, handle, is_connected, created_at)
            VALUES (?, ?, ?, 1, ?)
            """, (user_id, platform, handle.strip(), now))
            acc_id = cursor.lastrowid

        log_audit_event(user_id, "SOCIAL_ACCOUNT_CONNECTED", f"Linked {platform} handle {handle}")
        return {"success": True, "id": acc_id}

    @classmethod
    def get_user_social_accounts(cls, user_id: int) -> list:
        """Get list of connected social accounts."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM social_accounts WHERE user_id = ? ORDER BY id DESC", (user_id,))
            return [dict(r) for r in cursor.fetchall()]

    @classmethod
    def purge_user_data(cls, user_id: int) -> Dict[str, Any]:
        """
        Right-to-be-Forgotten / Total Data Deletion:
        Permanently purges all user media, hashes, alerts, matches, evidence, and account records.
        """
        # Delete user files on disk
        user_upload_sub = UPLOADS_DIR / str(user_id)
        if user_upload_sub.exists():
            shutil.rmtree(user_upload_sub, ignore_errors=True)

        user_evidence_sub = EVIDENCE_DIR / str(user_id)
        if user_evidence_sub.exists():
            shutil.rmtree(user_evidence_sub, ignore_errors=True)

        with get_db() as conn:
            # Foreign keys cascade will remove child records
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

        return {"success": True, "message": "All personal information, media, and records permanently deleted."}
