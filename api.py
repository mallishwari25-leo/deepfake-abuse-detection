"""
AEGIS-Social FastAPI REST Backend
Exposes comprehensive endpoints for user security, media fingerprinting,
deepfake forensics, multilingual harassment monitoring, and evidence preservation.
"""
import os
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from backend.config import APP_NAME, APP_VERSION, SUPPORTED_PLATFORMS, SUPPORTED_LANGUAGES
from backend.services.auth_service import AuthService
from backend.services.media_service import MediaService
from backend.services.social_monitor import SocialMonitoringService
from backend.services.alert_service import AlertService
from backend.services.evidence_service import EvidenceVaultService
from backend.services.sos_service import SOSSupportService
from backend.services.complaint_service import ConfidentialComplaintService
from backend.firebase_client import FirebaseClient
from backend.ai_engine.deepfake_detector import DeepfakeDetector
from backend.ai_engine.nlp_harassment import MultilingualHarassmentDetector
from PIL import Image
import io

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="AI-Powered Privacy-First Social Media Protection Engine"
)

# Enable CORS for local dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic Schemas ---
class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    full_name: str
    consent_given: bool = True
    country: str = "India"
    emergency_contact_name: Optional[str] = ""
    emergency_contact_phone: Optional[str] = ""
    emergency_contact_email: Optional[str] = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class VerifyOtpRequest(BaseModel):
    user_id: int
    otp_code: str


class TextScanRequest(BaseModel):
    user_id: int
    text: str
    platform: str = "Instagram"
    source_user: str = "@anon_user"
    post_url: str = "https://example.com/post/demo"
    is_simulated: bool = False

class ConnectAccountRequest(BaseModel):
    user_id: int
    platform: str
    handle: str

class PrivacySettingsRequest(BaseModel):
    user_id: int
    zero_retention: bool
    emergency_name: str
    emergency_phone: str
    emergency_email: str

class SealEvidenceRequest(BaseModel):
    user_id: int
    incident_title: str
    incident_type: str
    platform: str
    source_url: str
    evidence_data: dict

class FileComplaintRequest(BaseModel):
    user_id: int
    target_authority: str
    incident_type: str
    platform: str
    violating_url: str
    perpetrator_handle: Optional[str] = ""
    is_confidential: bool = True
    confidentiality_level: str = "Full Anonymity (Pseudonym)"
    relief_requested: str = "Immediate 24-Hour Content Takedown & Server IP Preservation"
    custom_statement: Optional[str] = ""
    evidence_vault_id: Optional[int] = None

class StatusUpdateRequest(BaseModel):
    status: str



# --- Endpoints ---

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "app": APP_NAME,
        "version": APP_VERSION,
        "supported_platforms": len(SUPPORTED_PLATFORMS),
        "supported_languages": len(SUPPORTED_LANGUAGES)
    }


# --- Authentication & Privacy ---

@app.post("/api/auth/register")
def register(req: RegisterRequest):
    res = AuthService.register_user(
        username=req.username,
        email=req.email,
        password=req.password,
        full_name=req.full_name,
        consent_given=req.consent_given,
        country=req.country,
        emergency_contact_name=req.emergency_contact_name or "",
        emergency_contact_phone=req.emergency_contact_phone or "",
        emergency_contact_email=req.emergency_contact_email or ""
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

@app.post("/api/auth/login")
def login(req: LoginRequest):
    res = AuthService.authenticate_user(req.username, req.password)
    if not res.get("success"):
        raise HTTPException(status_code=401, detail=res.get("error"))
    return res

@app.post("/api/auth/login-initiate")
def login_initiate(req: LoginRequest):
    """Step 1: Check username/password and issue 6-digit 2FA OTP."""
    res = AuthService.initiate_2fa_login(req.username, req.password)
    if not res.get("success"):
        raise HTTPException(status_code=401, detail=res.get("error"))
    return res

@app.post("/api/auth/login-verify-otp")
def login_verify_otp(req: VerifyOtpRequest):
    """Step 2: Verify 6-digit OTP code and create authenticated session."""
    res = AuthService.verify_otp_and_login(req.user_id, req.otp_code)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.get("/api/auth/profile/{user_id}")
def get_profile(user_id: int):
    user = AuthService.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    accounts = AuthService.get_user_social_accounts(user_id)
    return {"user": user, "connected_accounts": accounts}

@app.post("/api/auth/connect-account")
def connect_account(req: ConnectAccountRequest):
    res = AuthService.connect_social_account(req.user_id, req.platform, req.handle)
    return res

@app.post("/api/auth/privacy-settings")
def update_privacy(req: PrivacySettingsRequest):
    success = AuthService.update_privacy_settings(
        user_id=req.user_id,
        zero_retention=req.zero_retention,
        emergency_name=req.emergency_name,
        emergency_phone=req.emergency_phone,
        emergency_email=req.emergency_email
    )
    return {"success": success}

@app.post("/api/auth/purge/{user_id}")
def purge_account(user_id: int):
    """Right-to-be-forgotten total data destruction."""
    return AuthService.purge_user_data(user_id)


# --- Media Protection & Deepfakes ---

@app.post("/api/media/upload")
async def upload_media(
    user_id: int = Form(...),
    consent_confirmed: bool = Form(...),
    file: UploadFile = File(...)
):
    content = await file.read()
    res = MediaService.register_protected_media(
        user_id=user_id,
        filename=file.filename or "uploaded_media.jpg",
        file_bytes=content,
        media_type="image",
        consent_confirmed=consent_confirmed
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

@app.get("/api/media/list/{user_id}")
def list_user_media(user_id: int):
    return {"media": MediaService.get_user_media(user_id)}

@app.delete("/api/media/{media_id}")
def delete_media(media_id: int, user_id: int = Query(...)):
    success = MediaService.delete_protected_media(media_id, user_id)
    return {"success": success}

@app.post("/api/media/detect-deepfake")
async def detect_deepfake_file(file: UploadFile = File(...)):
    """Run ELA, FFT spectral analysis, and edge gradient inspection on an uploaded file."""
    content = await file.read()
    try:
        img = Image.open(io.BytesIO(content))
        results = DeepfakeDetector.analyze_image(img)
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process image: {str(e)}")

@app.get("/api/media/matches/{user_id}")
def get_user_matches(user_id: int):
    return {"matches": MediaService.get_user_matches(user_id)}

@app.post("/api/media/matches/{match_id}/status")
def update_match_status(match_id: int, user_id: int = Query(...), req: StatusUpdateRequest = None):
    if not req:
        raise HTTPException(status_code=400, detail="Missing status")
    success = MediaService.update_match_status(match_id, user_id, req.status)
    return {"success": success}


# --- Harassment & Social Media NLP ---

@app.post("/api/monitor/scan-text")
def scan_text(req: TextScanRequest):
    res = SocialMonitoringService.scan_comment(
        user_id=req.user_id,
        platform=req.platform,
        source_user=req.source_user,
        post_url=req.post_url,
        comment_text=req.text,
        is_simulated=req.is_simulated
    )
    return res

@app.get("/api/monitor/harassment-records/{user_id}")
def get_harassment_records(user_id: int, risk: Optional[str] = Query("ALL")):
    return {"records": SocialMonitoringService.get_user_harassment_records(user_id, risk)}

@app.post("/api/monitor/harassment-records/{record_id}/status")
def update_harassment_status(record_id: int, user_id: int = Query(...), req: StatusUpdateRequest = None):
    if not req:
        raise HTTPException(status_code=400, detail="Missing status")
    success = SocialMonitoringService.update_harassment_status(record_id, user_id, req.status)
    return {"success": success}


# --- Dashboard Telemetry & Alerts ---

@app.get("/api/dashboard/metrics/{user_id}")
def get_metrics(user_id: int):
    return AlertService.get_dashboard_metrics(user_id)

@app.get("/api/alerts/{user_id}")
def get_alerts(user_id: int, unread_only: bool = Query(False)):
    return {"alerts": AlertService.get_user_alerts(user_id, unread_only=unread_only)}

@app.post("/api/alerts/{alert_id}/action")
def update_alert(alert_id: int, user_id: int = Query(...), req: StatusUpdateRequest = None):
    if not req:
        raise HTTPException(status_code=400, detail="Missing status")
    success = AlertService.update_alert_status(alert_id, user_id, req.status)
    return {"success": success}


# --- Evidence Vault & SOS Support ---

@app.post("/api/evidence/seal")
def seal_evidence(req: SealEvidenceRequest):
    res = EvidenceVaultService.seal_incident_evidence(
        user_id=req.user_id,
        incident_title=req.incident_title,
        incident_type=req.incident_type,
        platform=req.platform,
        source_url=req.source_url,
        raw_evidence_dict=req.evidence_data
    )
    return res

@app.get("/api/evidence/list/{user_id}")
def get_vault_records(user_id: int):
    return {"vault_records": EvidenceVaultService.get_user_vault_records(user_id)}

@app.get("/api/evidence/{vault_id}/download")
def download_evidence_pdf(vault_id: int, user_id: int = Query(...)):
    records = EvidenceVaultService.get_user_vault_records(user_id)
    target = next((r for r in records if r["id"] == vault_id), None)
    if not target or not target.get("pdf_report_path") or not os.path.exists(target["pdf_report_path"]):
        raise HTTPException(status_code=404, detail="Evidence PDF not found on disk")
    return FileResponse(
        target["pdf_report_path"],
        media_type="application/pdf",
        filename=os.path.basename(target["pdf_report_path"])
    )

@app.get("/api/sos/directory")
def get_sos_directory(country: str = Query("India")):
    return SOSSupportService.get_emergency_info(country)


# --- Confidential Complaint & Legal Grievance Endpoints ---

@app.post("/api/complaints/file")
def file_complaint(req: FileComplaintRequest):
    """File a formal grievance petition with statutory victim confidentiality."""
    res = ConfidentialComplaintService.file_confidential_complaint(
        user_id=req.user_id,
        target_authority=req.target_authority,
        incident_type=req.incident_type,
        platform=req.platform,
        violating_url=req.violating_url,
        perpetrator_handle=req.perpetrator_handle or "",
        is_confidential=req.is_confidential,
        confidentiality_level=req.confidentiality_level,
        relief_requested=req.relief_requested,
        custom_statement=req.custom_statement or "",
        evidence_vault_id=req.evidence_vault_id
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res

@app.get("/api/complaints/list/{user_id}")
def list_complaints(user_id: int):
    """Retrieve all confidential complaints filed by user."""
    return {"complaints": ConfidentialComplaintService.get_user_complaints(user_id)}

@app.get("/api/complaints/{complaint_id}/download-pdf")
def download_complaint_pdf(complaint_id: int, user_id: int = Query(...)):
    """Download official court/intermediary-ready Confidential Complaint Petition PDF."""
    records = ConfidentialComplaintService.get_user_complaints(user_id)
    target = next((r for r in records if r["id"] == complaint_id), None)
    if not target or not target.get("pdf_complaint_path") or not os.path.exists(target["pdf_complaint_path"]):
        raise HTTPException(status_code=404, detail="Complaint PDF not found on disk")
    return FileResponse(
        target["pdf_complaint_path"],
        media_type="application/pdf",
        filename=os.path.basename(target["pdf_complaint_path"])
    )

@app.post("/api/complaints/{complaint_id}/status")
def update_complaint_status(complaint_id: int, user_id: int = Query(...), req: StatusUpdateRequest = None):
    if not req:
        raise HTTPException(status_code=400, detail="Missing status")
    success = ConfidentialComplaintService.update_complaint_status(complaint_id, user_id, req.status)
    return {"success": success}



# --- Firebase Cloud Integration Endpoints ---

@app.get("/api/firebase/status")
def get_firebase_status():
    """Verify live connectivity to Firebase Firestore."""
    return FirebaseClient.check_connection()

@app.post("/api/firebase/sync/{user_id}")
def sync_to_firebase(user_id: int):
    """Synchronize user alerts, matches, and evidence to Firebase Cloud Firestore."""
    return FirebaseClient.sync_all_to_firebase(user_id)

@app.get("/api/firebase/alerts")
def get_firebase_cloud_alerts():
    """Read safety alerts directly from Firebase Firestore cloud collection."""
    return {"cloud_alerts": FirebaseClient.get_documents("safety_alerts", page_size=20)}

