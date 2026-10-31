"""
AEGIS-Social Media Protection Service
Coordinates media uploads, privacy-preserving fingerprinting, misuse scanning, and forensic verification.
"""
import os
import io
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from PIL import Image

from backend.config import UPLOADS_DIR, ZERO_RETENTION_DEFAULT
from backend.database import get_db, log_audit_event
from backend.ai_engine.fingerprinting import MediaFingerprinter
from backend.ai_engine.deepfake_detector import DeepfakeDetector
from backend.ai_engine.content_moderator import VisualContentModerator
from backend.ai_engine.image_matcher import SocialMediaImageMatcher


class MediaService:
    """Manages protected photographs, video frames, and unauthorized distribution scans."""

    @classmethod
    def register_protected_media(
        cls,
        user_id: int,
        filename: str,
        file_bytes: bytes,
        media_type: str = "image",
        consent_confirmed: bool = False
    ) -> Dict[str, Any]:
        """
        Processes uploaded photograph or video:
        1. Verifies explicit consent.
        2. Computes privacy-preserving digital fingerprints (pHash, dHash, aHash, wHash, SHA-256).
        3. Runs initial baseline moderation and deepfake artifact scan.
        4. Saves media (or discards raw file if zero retention is enabled).
        """
        if not consent_confirmed:
            return {"success": False, "error": "Explicit user consent is required before processing media."}

        # Check user zero-retention preference
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT zero_retention_enabled FROM users WHERE id = ?", (user_id,))
            user_row = cursor.fetchone()
            zero_retention = bool(user_row["zero_retention_enabled"]) if user_row else ZERO_RETENTION_DEFAULT

        # Fingerprint
        try:
            fp = MediaFingerprinter.fingerprint_image_bytes(file_bytes)
        except Exception as e:
            return {"success": False, "error": f"Failed to decode image: {str(e)}"}

        # Moderation check on baseline
        img = Image.open(io.BytesIO(file_bytes))
        moderation_result = VisualContentModerator.moderate_media(img)
        baseline_forensics = DeepfakeDetector.analyze_image(img)

        # File storage
        file_path = None
        if not zero_retention:
            user_folder = UPLOADS_DIR / str(user_id)
            user_folder.mkdir(parents=True, exist_ok=True)
            safe_name = f"{int(datetime.now().timestamp())}_{filename}"
            target_path = user_folder / safe_name
            with open(target_path, "wb") as f:
                f.write(file_bytes)
            file_path = str(target_path)

        now = datetime.now().isoformat()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO protected_media (
                user_id, filename, media_type, file_sha256,
                phash, dhash, ahash, whash, video_keyframe_hashes,
                file_path, upload_timestamp, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (
                user_id,
                filename,
                media_type,
                fp["file_sha256"],
                fp["phash"],
                fp["dhash"],
                fp["ahash"],
                fp["whash"],
                json.dumps([]),
                file_path,
                now
            ))
            media_id = cursor.lastrowid

        log_audit_event(user_id, "MEDIA_PROTECTED", f"Registered media ID={media_id} (ZeroRetention={zero_retention})")

        return {
            "success": True,
            "media_id": media_id,
            "fingerprint": fp,
            "moderation": moderation_result,
            "baseline_forensics": baseline_forensics,
            "zero_retention": zero_retention,
            "stored_path": file_path
        }

    @classmethod
    def get_user_media(cls, user_id: int) -> List[Dict[str, Any]]:
        """Retrieve list of active protected media for user."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM protected_media WHERE user_id = ? AND is_active = 1 ORDER BY id DESC", (user_id,))
            return [dict(r) for r in cursor.fetchall()]

    @classmethod
    def delete_protected_media(cls, media_id: int, user_id: int) -> bool:
        """Delete specific protected media and remove from disk."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_path FROM protected_media WHERE id = ? AND user_id = ?", (media_id, user_id))
            row = cursor.fetchone()
            if row and row["file_path"] and os.path.exists(row["file_path"]):
                try:
                    os.remove(row["file_path"])
                except Exception:
                    pass
            cursor.execute("DELETE FROM protected_media WHERE id = ? AND user_id = ?", (media_id, user_id))
        log_audit_event(user_id, "MEDIA_DELETED", f"Deleted media ID={media_id}")
        return True

    @classmethod
    def record_scan_match(
        cls,
        media_id: Optional[int],
        user_id: int,
        source_platform: str,
        post_url: str,
        matched_media_path: str,
        match_confidence: float,
        similarity_metric: str,
        risk_level: str,
        risk_explanation: str,
        is_manipulated: bool,
        manipulation_score: float,
        manipulation_details: str,
        is_simulated: bool = False
    ) -> int:
        """Record an unauthorized redistribution or deepfake detection in the database."""
        now = datetime.now().isoformat()
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO scan_matches (
                media_id, user_id, source_platform, post_url,
                matched_media_path, match_confidence, similarity_metric,
                risk_level, risk_explanation, is_manipulated,
                manipulation_score, manipulation_details, is_simulated,
                status, detected_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?)
            """, (
                media_id, user_id, source_platform, post_url,
                matched_media_path, match_confidence, similarity_metric,
                risk_level, risk_explanation, 1 if is_manipulated else 0,
                manipulation_score, manipulation_details, 1 if is_simulated else 0,
                now
            ))
            match_id = cursor.lastrowid

            # Also create an immediate safety alert
            cursor.execute("""
            INSERT INTO safety_alerts (
                user_id, title, alert_type, platform, source_url,
                risk_level, confidence, explanation, related_item_id,
                is_read, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'new', ?)
            """, (
                user_id,
                f"Potential {risk_level} Incident on {source_platform}",
                "deepfake" if is_manipulated else "misuse",
                source_platform,
                post_url,
                risk_level,
                match_confidence,
                risk_explanation,
                match_id,
                now
            ))

        log_audit_event(user_id, "SCAN_MATCH_RECORDED", f"Match ID={match_id} Risk={risk_level} Platform={source_platform}")
        return match_id

    @classmethod
    def get_user_matches(cls, user_id: int) -> List[Dict[str, Any]]:
        """Get all scan matches for a user."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT m.*, p.filename as original_filename, p.file_path as original_file_path
            FROM scan_matches m
            LEFT JOIN protected_media p ON m.media_id = p.id
            WHERE m.user_id = ?
            ORDER BY m.id DESC
            """, (user_id,))
            return [dict(r) for r in cursor.fetchall()]

    @classmethod
    def update_match_status(cls, match_id: int, user_id: int, status: str) -> bool:
        """Update match status ('confirmed', 'dismissed_false_positive')."""
        with get_db() as conn:
            conn.execute(
                "UPDATE scan_matches SET status = ? WHERE id = ? AND user_id = ?",
                (status, match_id, user_id)
            )
        log_audit_event(user_id, "MATCH_STATUS_UPDATED", f"Match ID={match_id} set to {status}")
        return True
