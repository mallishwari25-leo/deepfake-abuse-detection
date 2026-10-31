"""
AEGIS-Social Instant Safety Alert & Metrics Service
Provides incident dispatching, confirmation workflows, false-positive appeals, and dashboard metrics.
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from backend.database import get_db, log_audit_event


class AlertService:
    """Manages real-time safety alerts and aggregated telemetry statistics."""

    @classmethod
    def get_user_alerts(
        cls,
        user_id: int,
        unread_only: bool = False,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Fetch alert feed for user."""
        with get_db() as conn:
            cursor = conn.cursor()
            if unread_only:
                cursor.execute("""
                SELECT * FROM safety_alerts
                WHERE user_id = ? AND is_read = 0
                ORDER BY id DESC LIMIT ?
                """, (user_id, limit))
            else:
                cursor.execute("""
                SELECT * FROM safety_alerts
                WHERE user_id = ?
                ORDER BY id DESC LIMIT ?
                """, (user_id, limit))
            return [dict(r) for r in cursor.fetchall()]

    @classmethod
    def mark_alert_read(cls, alert_id: int, user_id: int) -> bool:
        """Mark specific alert as read."""
        with get_db() as conn:
            conn.execute("UPDATE safety_alerts SET is_read = 1 WHERE id = ? AND user_id = ?", (alert_id, user_id))
        return True

    @classmethod
    def update_alert_status(cls, alert_id: int, user_id: int, status: str) -> bool:
        """Update alert status (e.g., 'acknowledged', 'reported', 'dismissed')."""
        with get_db() as conn:
            conn.execute("UPDATE safety_alerts SET status = ?, is_read = 1 WHERE id = ? AND user_id = ?", (status, alert_id, user_id))
        log_audit_event(user_id, "ALERT_STATUS_UPDATED", f"Alert ID={alert_id} set to {status}")
        return True

    @classmethod
    def get_dashboard_metrics(cls, user_id: int) -> Dict[str, Any]:
        """
        Calculates all real-time safety dashboard metrics required:
        - Total media items monitored
        - Potentially unauthorized media matches
        - Suspected deepfake detections
        - Abusive comments detected
        - Threatening messages identified
        - Platform-wise incident distribution
        - Recent safety alerts
        - Overall safety status
        """
        with get_db() as conn:
            cursor = conn.cursor()

            # 1. Total Media Monitored
            cursor.execute("SELECT COUNT(*) FROM protected_media WHERE user_id = ? AND is_active = 1", (user_id,))
            total_media = cursor.fetchone()[0]

            # 2. Potentially Unauthorized Matches
            cursor.execute("SELECT COUNT(*) FROM scan_matches WHERE user_id = ? AND status != 'dismissed_false_positive'", (user_id,))
            total_matches = cursor.fetchone()[0]

            # 3. Suspected Deepfakes
            cursor.execute("SELECT COUNT(*) FROM scan_matches WHERE user_id = ? AND is_manipulated = 1 AND status != 'dismissed_false_positive'", (user_id,))
            deepfake_count = cursor.fetchone()[0]

            # 4. Abusive Comments Detected (ORANGE & YELLOW)
            cursor.execute("SELECT COUNT(*) FROM harassment_records WHERE user_id = ? AND risk_level IN ('YELLOW', 'ORANGE') AND status != 'appealed_false_positive'", (user_id,))
            abusive_comments = cursor.fetchone()[0]

            # 5. Threatening Messages (RED)
            cursor.execute("SELECT COUNT(*) FROM harassment_records WHERE user_id = ? AND risk_level = 'RED' AND status != 'appealed_false_positive'", (user_id,))
            threatening_messages = cursor.fetchone()[0]

            # 6. Platform distribution (from matches and harassment)
            cursor.execute("""
            SELECT platform, COUNT(*) as count FROM (
                SELECT source_platform as platform FROM scan_matches WHERE user_id = ?
                UNION ALL
                SELECT platform FROM harassment_records WHERE user_id = ?
            ) GROUP BY platform
            """, (user_id, user_id))
            platform_rows = cursor.fetchall()
            platform_dist = {r["platform"]: r["count"] for r in platform_rows}

            # 7. Unread alerts count
            cursor.execute("SELECT COUNT(*) FROM safety_alerts WHERE user_id = ? AND is_read = 0", (user_id,))
            unread_alerts = cursor.fetchone()[0]

            # 8. Overall Safety Status
            if threatening_messages > 0:
                overall_status = {"level": "CRITICAL", "color": "#EF4444", "badge": "🔴 CRITICAL THREAT DETECTED", "action_needed": True}
            elif deepfake_count > 0 or abusive_comments >= 3:
                overall_status = {"level": "ELEVATED", "color": "#F97316", "badge": "🟠 ELEVATED ATTENTION REQUIRED", "action_needed": True}
            elif total_matches > 0 or abusive_comments > 0:
                overall_status = {"level": "LOW", "color": "#F59E0B", "badge": "🟡 LOW - REVIEW ACTIVE ALERTS", "action_needed": False}
            else:
                overall_status = {"level": "SAFE", "color": "#10B981", "badge": "🟢 SECURE - NO ACTIVE THREATS", "action_needed": False}

        return {
            "total_media": total_media,
            "total_matches": total_matches,
            "deepfake_count": deepfake_count,
            "abusive_comments": abusive_comments,
            "threatening_messages": threatening_messages,
            "platform_distribution": platform_dist,
            "unread_alerts": unread_alerts,
            "overall_status": overall_status
        }
