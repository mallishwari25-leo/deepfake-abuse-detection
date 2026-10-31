"""
AEGIS-Social: AI Cyber-Shield & Privacy Protection Platform
Configuration and Security Settings
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"
UPLOADS_DIR = BASE_DIR / "uploads"
EVIDENCE_DIR = BASE_DIR / "evidence_vault_storage"
DATABASE_PATH = BASE_DIR / "aegis_protection.db"
SAMPLE_DATA_DIR = BASE_DIR / "sample_data"

# Ensure runtime directories exist
for p in [UPLOADS_DIR, EVIDENCE_DIR, SAMPLE_DATA_DIR]:
    p.mkdir(parents=True, exist_ok=True)

# Application Metadata
APP_NAME = "AEGIS-GUARD"
APP_SUBTITLE = "AI-Powered Privacy-First Social Media Protection"
APP_VERSION = "2.4.0-PROD"

# Security & Crypto
SECRET_KEY = os.environ.get("AEGIS_SECRET_KEY", "aegis-defense-shield-secure-key-2026-sha256")
PASSWORD_SALT_BYTES = 16
PBKDF2_ITERATIONS = 120_000
SESSION_EXPIRY_HOURS = 24

# Risk Levels & Color Badges
RISK_LEVELS = {
    "GREEN": {"name": "Safe", "color": "#10B981", "badge": "🟢 SAFE", "severity": 0},
    "YELLOW": {"name": "Suspicious / Potential Inappropriate", "color": "#F59E0B", "badge": "🟡 CAUTION", "severity": 1},
    "ORANGE": {"name": "Abusive / Manipulated Content", "color": "#F97316", "badge": "🟠 ELEVATED RISK", "severity": 2},
    "RED": {"name": "Severe Threat / Explicit Abuse", "color": "#EF4444", "badge": "🔴 HIGH SEVERITY / DANGER", "severity": 3},
}

# Supported Social Platforms
SUPPORTED_PLATFORMS = [
    {"id": "instagram", "name": "Instagram", "icon": "📸", "api_available": True},
    {"id": "twitter", "name": "X / Twitter", "icon": "🐦", "api_available": True},
    {"id": "reddit", "name": "Reddit", "icon": "🤖", "api_available": True},
    {"id": "youtube", "name": "YouTube", "icon": "▶️", "api_available": True},
    {"id": "facebook", "name": "Facebook", "icon": "👥", "api_available": True},
    {"id": "telegram", "name": "Telegram (Public Channels)", "icon": "✈️", "api_available": True},
]

# Supported Languages for NLP Moderation
SUPPORTED_LANGUAGES = [
    {"code": "en", "name": "English"},
    {"code": "hi", "name": "Hindi (हिंदी)"},
    {"code": "te", "name": "Telugu (తెలుగు)"},
    {"code": "ta", "name": "Tamil (தமிழ்)"},
    {"code": "hinglish", "name": "Hinglish (Code-Mixed)"},
    {"code": "tenglish", "name": "Tenglish (Telugu-English)"},
    {"code": "tanglish", "name": "Tanglish (Tamil-English)"},
]

# Privacy & Compliance
CONSENT_VERSION = "v2.1-DPDPA-2023"
FACIAL_RECOGNITION_ALLOWED_FOR_STRANGERS = False
ZERO_RETENTION_DEFAULT = False
MAX_UPLOAD_SIZE_MB = 50

# Firebase Cloud Database Configuration
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyAUV054elt6_J-Kbaq64LOj3a9Aa9dUu3g",
    "authDomain": "deepfake-abuse-detection.firebaseapp.com",
    "projectId": "deepfake-abuse-detection",
    "storageBucket": "deepfake-abuse-detection.firebasestorage.app",
    "messagingSenderId": "916842208704",
    "appId": "1:916842208704:web:e19c17f3dbebf8b8c1fc25",
    "measurementId": "G-DWZK1LYDSD"
}
FIREBASE_FIRESTORE_URL = f"https://firestore.googleapis.com/v1/projects/{FIREBASE_CONFIG['projectId']}/databases/(default)/documents"

