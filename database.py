"""
AEGIS-Social Database Engine
Manages SQLite schema, migrations, connection lifecycle, and transaction helpers.
"""
import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime
from backend.config import DATABASE_PATH


@contextmanager
def get_db():
    """Context manager for SQLite connections with row dict factory and WAL mode."""
    conn = sqlite3.connect(DATABASE_PATH, timeout=20.0)
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging for fast concurrent reads and writes
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize all schema tables and indexes."""
    with get_db() as conn:
        cursor = conn.cursor()

        # 1. Users Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            consent_given INTEGER DEFAULT 0,
            consent_timestamp TEXT,
            zero_retention_enabled INTEGER DEFAULT 0,
            emergency_contact_name TEXT,
            emergency_contact_phone TEXT,
            emergency_contact_email TEXT,
            country TEXT DEFAULT 'India'
        );
        """)

        # 2. Social Accounts Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS social_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            handle TEXT NOT NULL,
            is_connected INTEGER DEFAULT 1,
            last_monitored_at TEXT,
            monitor_enabled INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # 3. Protected Media Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS protected_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            media_type TEXT NOT NULL, -- 'image' or 'video'
            file_sha256 TEXT NOT NULL,
            phash TEXT,
            dhash TEXT,
            ahash TEXT,
            whash TEXT,
            video_keyframe_hashes TEXT, -- JSON array of frame hashes
            file_path TEXT,
            upload_timestamp TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # 4. Scan Matches (Image Misuse & Redistribution)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            media_id INTEGER,
            user_id INTEGER NOT NULL,
            source_platform TEXT NOT NULL,
            post_url TEXT NOT NULL,
            matched_media_path TEXT,
            match_confidence REAL NOT NULL,
            similarity_metric TEXT,
            risk_level TEXT NOT NULL, -- GREEN, YELLOW, ORANGE, RED
            risk_explanation TEXT NOT NULL,
            is_manipulated INTEGER DEFAULT 0,
            manipulation_score REAL DEFAULT 0.0,
            manipulation_details TEXT,
            is_simulated INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending_review', -- 'pending_review', 'confirmed', 'dismissed_false_positive'
            detected_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(media_id) REFERENCES protected_media(id) ON DELETE SET NULL
        );
        """)

        # 5. Harassment Records
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS harassment_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            platform TEXT NOT NULL,
            source_user TEXT NOT NULL,
            post_url TEXT NOT NULL,
            comment_text TEXT NOT NULL,
            detected_language TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            categories TEXT NOT NULL, -- JSON array of categories
            explanation TEXT NOT NULL,
            is_simulated INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active', -- 'active', 'reviewed', 'appealed_false_positive', 'vaulted'
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # 6. Safety Alerts
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS safety_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            alert_type TEXT NOT NULL, -- 'misuse', 'deepfake', 'harassment', 'threat'
            platform TEXT NOT NULL,
            source_url TEXT,
            risk_level TEXT NOT NULL,
            confidence REAL NOT NULL,
            explanation TEXT NOT NULL,
            related_item_id INTEGER,
            is_read INTEGER DEFAULT 0,
            status TEXT DEFAULT 'new', -- 'new', 'acknowledged', 'reported', 'dismissed'
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # 7. Evidence Vault
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence_vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            incident_title TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            platform TEXT NOT NULL,
            source_url TEXT,
            evidence_data_json TEXT NOT NULL,
            tamper_seal_hash TEXT NOT NULL,
            chain_of_custody_log TEXT NOT NULL,
            pdf_report_path TEXT,
            created_at TEXT NOT NULL,
            sealed_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # 8. Audit Logs
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT DEFAULT '127.0.0.1',
            timestamp TEXT NOT NULL
        );
        """)

        # 9. Confidential Complaints Table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            complaint_ref_no TEXT UNIQUE NOT NULL,
            target_authority TEXT NOT NULL,
            incident_type TEXT NOT NULL,
            platform TEXT NOT NULL,
            violating_url TEXT NOT NULL,
            perpetrator_handle TEXT,
            is_confidential INTEGER DEFAULT 1,
            complainant_pseudonym TEXT NOT NULL,
            confidentiality_level TEXT DEFAULT 'Full Anonymity (Pseudonym)',
            legal_clauses TEXT NOT NULL, -- JSON array of legal sections
            relief_requested TEXT NOT NULL,
            complaint_statement TEXT NOT NULL,
            evidence_vault_id INTEGER,
            tamper_seal_hash TEXT NOT NULL,
            pdf_complaint_path TEXT,
            status TEXT DEFAULT 'drafted', -- 'drafted', 'filed', 'under_investigation', 'resolved'
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """)

        # Indexes for fast querying
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_media_user ON protected_media(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_user ON safety_alerts(user_id, is_read);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_harass_user ON harassment_records(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_matches_user ON scan_matches(user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_complaints_user ON complaints(user_id);")


def log_audit_event(user_id: int, action: str, details: str = "", ip: str = "127.0.0.1"):
    """Record an immutable security audit event."""
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit_logs (user_id, action, details, ip_address, timestamp) VALUES (?, ?, ?, ?, ?)",
                (user_id, action, details, ip, datetime.now().isoformat())
            )
    except Exception as e:
        print(f"Failed to record audit log: {e}")
