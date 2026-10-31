"""
AEGIS-Social Firebase Cloud Database Client
Provides real-time cloud synchronization with Google Firebase Firestore.
Synchronizes safety alerts, protected media fingerprints, harassment telemetry, and evidence records.
"""
import requests
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.config import FIREBASE_CONFIG, FIREBASE_FIRESTORE_URL
from backend.database import get_db, log_audit_event


class FirebaseClient:
    """Manages cloud synchronization and data exchange with Firebase Firestore."""

    API_KEY = FIREBASE_CONFIG["apiKey"]
    PROJECT_ID = FIREBASE_CONFIG["projectId"]
    BASE_URL = FIREBASE_FIRESTORE_URL

    @classmethod
    def check_connection(cls) -> Dict[str, Any]:
        """Test connection to Firebase Firestore."""
        try:
            url = f"{cls.BASE_URL}/system_status"
            params = {"key": cls.API_KEY}
            resp = requests.get(url, params=params, timeout=5.0)
            if resp.status_code == 200:
                return {
                    "connected": True,
                    "project_id": cls.PROJECT_ID,
                    "auth_domain": FIREBASE_CONFIG["authDomain"],
                    "storage_bucket": FIREBASE_CONFIG["storageBucket"],
                    "status_code": resp.status_code,
                    "message": "Firebase Firestore is connected and reachable."
                }
            else:
                return {
                    "connected": False,
                    "project_id": cls.PROJECT_ID,
                    "status_code": resp.status_code,
                    "error": resp.text[:150]
                }
        except Exception as e:
            return {
                "connected": False,
                "project_id": cls.PROJECT_ID,
                "error": str(e)
            }

    @classmethod
    def _py_to_firestore_value(cls, val: Any) -> dict:
        """Convert a single Python primitive to Firestore REST typed format."""
        if val is None:
            return {"nullValue": None}
        elif isinstance(val, bool):
            return {"booleanValue": val}
        elif isinstance(val, int):
            return {"integerValue": str(val)}
        elif isinstance(val, float):
            return {"doubleValue": val}
        elif isinstance(val, str):
            return {"stringValue": val}
        elif isinstance(val, dict):
            return {"mapValue": {"fields": {k: cls._py_to_firestore_value(v) for k, v in val.items()}}}
        elif isinstance(val, (list, tuple)):
            return {"arrayValue": {"values": [cls._py_to_firestore_value(x) for x in val]}}
        else:
            return {"stringValue": str(val)}

    @classmethod
    def _firestore_value_to_py(cls, val_dict: dict) -> Any:
        """Convert Firestore typed value back to Python primitive."""
        if "stringValue" in val_dict:
            return val_dict["stringValue"]
        elif "integerValue" in val_dict:
            return int(val_dict["integerValue"])
        elif "doubleValue" in val_dict:
            return float(val_dict["doubleValue"])
        elif "booleanValue" in val_dict:
            return bool(val_dict["booleanValue"])
        elif "nullValue" in val_dict:
            return None
        elif "mapValue" in val_dict:
            fields = val_dict["mapValue"].get("fields", {})
            return {k: cls._firestore_value_to_py(v) for k, v in fields.items()}
        elif "arrayValue" in val_dict:
            values = val_dict["arrayValue"].get("values", [])
            return [cls._firestore_value_to_py(x) for x in values]
        return None

    @classmethod
    def save_document(cls, collection: str, doc_id: str, data: dict) -> Dict[str, Any]:
        """Save or overwrite a document in Firebase Firestore."""
        try:
            url = f"{cls.BASE_URL}/{collection}/{doc_id}"
            params = {"key": cls.API_KEY}
            fields = {k: cls._py_to_firestore_value(v) for k, v in data.items()}
            payload = {"fields": fields}
            resp = requests.patch(url, params=params, json=payload, timeout=8.0)
            if resp.status_code == 200:
                return {"success": True, "name": resp.json().get("name")}
            return {"success": False, "status_code": resp.status_code, "error": resp.text[:150]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    def add_document(cls, collection: str, data: dict) -> Dict[str, Any]:
        """Add a document to a Firestore collection with an auto-generated ID."""
        try:
            url = f"{cls.BASE_URL}/{collection}"
            params = {"key": cls.API_KEY}
            fields = {k: cls._py_to_firestore_value(v) for k, v in data.items()}
            payload = {"fields": fields}
            resp = requests.post(url, params=params, json=payload, timeout=8.0)
            if resp.status_code == 200:
                doc_name = resp.json().get("name", "")
                doc_id = doc_name.split("/")[-1] if doc_name else ""
                return {"success": True, "doc_id": doc_id, "name": doc_name}
            return {"success": False, "status_code": resp.status_code, "error": resp.text[:150]}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @classmethod
    def get_documents(cls, collection: str, page_size: int = 50) -> List[Dict[str, Any]]:
        """Fetch documents from a Firestore collection."""
        try:
            url = f"{cls.BASE_URL}/{collection}"
            params = {"key": cls.API_KEY, "pageSize": page_size}
            resp = requests.get(url, params=params, timeout=8.0)
            if resp.status_code == 200:
                docs = resp.json().get("documents", [])
                results = []
                for d in docs:
                    doc_id = d.get("name", "").split("/")[-1]
                    fields = d.get("fields", {})
                    py_data = {k: cls._firestore_value_to_py(v) for k, v in fields.items()}
                    py_data["_firestore_id"] = doc_id
                    results.append(py_data)
                return results
            return []
        except Exception:
            return []

    @classmethod
    def sync_all_to_firebase(cls, user_id: int) -> Dict[str, Any]:
        """
        Pushes local security events, alerts, and protected media fingerprints
        to Firebase Cloud Firestore for real-time remote cloud backup.
        """
        stats = {"alerts_synced": 0, "matches_synced": 0, "harassment_synced": 0, "vault_synced": 0}

        with get_db() as conn:
            cursor = conn.cursor()

            # 1. Sync Safety Alerts
            cursor.execute("SELECT * FROM safety_alerts WHERE user_id = ?", (user_id,))
            alerts = cursor.fetchall()
            for a in alerts:
                doc_data = {
                    "alert_id": a["id"],
                    "user_id": a["user_id"],
                    "title": a["title"],
                    "alert_type": a["alert_type"],
                    "platform": a["platform"],
                    "source_url": a["source_url"] or "",
                    "risk_level": a["risk_level"],
                    "confidence": float(a["confidence"]),
                    "explanation": a["explanation"],
                    "is_read": bool(a["is_read"]),
                    "status": a["status"],
                    "created_at": a["created_at"],
                    "synced_at": datetime.now().isoformat()
                }
                res = cls.save_document("safety_alerts", f"alert_{a['id']}", doc_data)
                if res.get("success"):
                    stats["alerts_synced"] += 1

            # 2. Sync Scan Matches (Redistribution & Deepfakes)
            cursor.execute("SELECT * FROM scan_matches WHERE user_id = ?", (user_id,))
            matches = cursor.fetchall()
            for m in matches:
                doc_data = {
                    "match_id": m["id"],
                    "user_id": m["user_id"],
                    "source_platform": m["source_platform"],
                    "post_url": m["post_url"],
                    "match_confidence": float(m["match_confidence"]),
                    "risk_level": m["risk_level"],
                    "risk_explanation": m["risk_explanation"],
                    "is_manipulated": bool(m["is_manipulated"]),
                    "manipulation_score": float(m["manipulation_score"]),
                    "is_simulated": bool(m["is_simulated"]),
                    "status": m["status"],
                    "detected_at": m["detected_at"],
                    "synced_at": datetime.now().isoformat()
                }
                res = cls.save_document("scan_matches", f"match_{m['id']}", doc_data)
                if res.get("success"):
                    stats["matches_synced"] += 1

            # 3. Sync Harassment Records
            cursor.execute("SELECT * FROM harassment_records WHERE user_id = ?", (user_id,))
            harass = cursor.fetchall()
            for h in harass:
                doc_data = {
                    "record_id": h["id"],
                    "user_id": h["user_id"],
                    "platform": h["platform"],
                    "source_user": h["source_user"],
                    "post_url": h["post_url"],
                    "comment_text": h["comment_text"],
                    "detected_language": h["detected_language"],
                    "risk_level": h["risk_level"],
                    "confidence_score": float(h["confidence_score"]),
                    "explanation": h["explanation"],
                    "is_simulated": bool(h["is_simulated"]),
                    "status": h["status"],
                    "timestamp": h["timestamp"],
                    "synced_at": datetime.now().isoformat()
                }
                res = cls.save_document("harassment_records", f"harass_{h['id']}", doc_data)
                if res.get("success"):
                    stats["harassment_synced"] += 1

            # 4. Sync Evidence Vault (Public metadata & seal hash only - zero sensitive files)
            cursor.execute("SELECT id, incident_title, incident_type, platform, source_url, tamper_seal_hash, sealed_at FROM evidence_vault WHERE user_id = ?", (user_id,))
            vault_records = cursor.fetchall()
            for v in vault_records:
                doc_data = {
                    "vault_id": v["id"],
                    "incident_title": v["incident_title"],
                    "incident_type": v["incident_type"],
                    "platform": v["platform"],
                    "source_url": v["source_url"] or "",
                    "tamper_seal_hash": v["tamper_seal_hash"],
                    "sealed_at": v["sealed_at"],
                    "synced_at": datetime.now().isoformat()
                }
                res = cls.save_document("evidence_vault", f"case_{v['id']}", doc_data)
                if res.get("success"):
                    stats["vault_synced"] += 1

            # 5. Sync System Status Document
            status_doc = {
                "app": "AEGIS-GUARD",
                "project_id": cls.PROJECT_ID,
                "user_id": user_id,
                "last_cloud_sync": datetime.now().isoformat(),
                "total_alerts": len(alerts),
                "total_matches": len(matches),
                "total_harassment": len(harass),
                "total_vault": len(vault_records),
                "status": "ONLINE_SYNCED"
            }
            cls.save_document("system_status", "telemetry_summary", status_doc)

        log_audit_event(user_id, "FIREBASE_SYNC_COMPLETED", f"Synced: {stats}")
        return {
            "success": True,
            "project_id": cls.PROJECT_ID,
            "stats": stats,
            "synced_at": datetime.now().isoformat()
        }
