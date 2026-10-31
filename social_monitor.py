"""
AEGIS-Social Media Harassment & Toxicity Monitoring Service
Monitors social accounts, analyzes comments/mentions using NLP engine, and dispatches safety alerts.
"""
from datetime import datetime
import json
from typing import List, Dict, Any, Optional

from backend.database import get_db, log_audit_event
from backend.ai_engine.nlp_harassment import MultilingualHarassmentDetector


class SocialMonitoringService:
    """Monitors live and authorized feed comments, mentions, and captions for harassment."""

    @classmethod
    def scan_comment(
        cls,
        user_id: int,
        platform: str,
        source_user: str,
        post_url: str,
        comment_text: str,
        is_simulated: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze an incoming comment or mention using Multilingual NLP:
        1. Classifies into categories (insult, threat, cyberbullying, body shaming, gender abuse, hate speech, etc.).
        2. Assigns standard GREEN, YELLOW, ORANGE, RED risk level.
        3. Saves record and dispatches alert if flagged.
        """
        analysis = MultilingualHarassmentDetector.analyze_text(comment_text)
        now = datetime.now().isoformat()

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO harassment_records (
                user_id, platform, source_user, post_url,
                comment_text, detected_language, risk_level,
                confidence_score, categories, explanation,
                is_simulated, status, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
            """, (
                user_id, platform, source_user, post_url,
                comment_text, analysis["detected_language"], analysis["risk_level"],
                analysis["confidence_score"], json.dumps(analysis["categories"]),
                analysis["explanation"], 1 if is_simulated else 0, now
            ))
            record_id = cursor.lastrowid

            # Dispatch alert for YELLOW, ORANGE, RED
            if analysis["risk_level"] in ["YELLOW", "ORANGE", "RED"]:
                cursor.execute("""
                INSERT INTO safety_alerts (
                    user_id, title, alert_type, platform, source_url,
                    risk_level, confidence, explanation, related_item_id,
                    is_read, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'new', ?)
                """, (
                    user_id,
                    f"Abusive Content Detected on {platform} ({analysis['risk_level']})",
                    "threat" if analysis["risk_level"] == "RED" else "harassment",
                    platform,
                    post_url,
                    analysis["risk_level"],
                    analysis["confidence_score"],
                    analysis["explanation"],
                    record_id,
                    now
                ))

        log_audit_event(user_id, "COMMENT_SCANNED", f"Record ID={record_id} Risk={analysis['risk_level']} Lang={analysis['detected_language']}")

        return {
            "record_id": record_id,
            "analysis": analysis,
            "platform": platform,
            "source_user": source_user,
            "post_url": post_url
        }

    @classmethod
    def get_user_harassment_records(
        cls,
        user_id: int,
        risk_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve harassment records for user, optionally filtered by risk level."""
        with get_db() as conn:
            cursor = conn.cursor()
            if risk_filter and risk_filter != "ALL":
                cursor.execute("""
                SELECT * FROM harassment_records
                WHERE user_id = ? AND risk_level = ?
                ORDER BY id DESC
                """, (user_id, risk_filter))
            else:
                cursor.execute("""
                SELECT * FROM harassment_records
                WHERE user_id = ?
                ORDER BY id DESC
                """, (user_id,))

            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["categories"] = json.loads(item["categories"])
                except Exception:
                    item["categories"] = []
                results.append(item)
            return results

    @classmethod
    def update_harassment_status(cls, record_id: int, user_id: int, status: str) -> bool:
        """Update harassment record status (e.g., 'reviewed', 'appealed_false_positive')."""
        with get_db() as conn:
            conn.execute(
                "UPDATE harassment_records SET status = ? WHERE id = ? AND user_id = ?",
                (status, record_id, user_id)
            )
        log_audit_event(user_id, "HARASSMENT_STATUS_UPDATED", f"Record ID={record_id} set to {status}")
        return True
