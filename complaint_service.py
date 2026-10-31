"""
AEGIS-Social Confidential Complaint & Legal Grievance Filing Service
Enables users to file formal complaints and 24-hour takedown notices with law enforcement and platform grievance officers.
Ensures strict victim confidentiality, anonymity tokenization, and statutory identity protection.
"""
import os
import json
import secrets
from datetime import datetime
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.config import EVIDENCE_DIR, APP_NAME, APP_VERSION
from backend.database import get_db, log_audit_event
from backend.security import sign_evidence_record, compute_bytes_sha256
from backend.services.auth_service import AuthService
from backend.services.evidence_service import EvidenceVaultService
from backend.firebase_client import FirebaseClient


class ConfidentialComplaintService:
    """Manages anonymous/confidential legal complaints, takedown notices, and petition generation."""

    AUTHORITIES = [
        {
            "id": "cybercrime_portal",
            "name": "National Cyber Crime Reporting Portal (cybercrime.gov.in) & Cyber Police Cell",
            "statutory_scope": "Criminal investigation, FIR registration, and preservation of ISP/telecom logs under Indian IT Act and Bharatiya Nyaya Sanhita (BNS)."
        },
        {
            "id": "platform_grievance",
            "name": "Social Media Intermediary Grievance Officer (Meta / X / Reddit / Google)",
            "statutory_scope": "Mandatory 24-hour expedited content removal under Rule 3(2) of IT (Intermediary Guidelines) Rules 2021 and DMCA takedown."
        },
        {
            "id": "ncw_cyber",
            "name": "National Commission for Women (NCW) Cyber Crime Cell",
            "statutory_scope": "Women's digital safety grievance, institutional escalation, and legal advocacy."
        },
        {
            "id": "stop_ncii",
            "name": "StopNCII.org Global Hash Removal Network",
            "statutory_scope": "On-device non-reversible cryptographic hash propagation across global partner platforms to prevent intimate imagery circulation."
        }
    ]

    LEGAL_PROVISIONS = {
        "deepfake": [
            "Section 66D IT Act: Cheating by personation using computer resource (up to 3 years imprisonment)",
            "Section 66E IT Act: Violation of bodily privacy and capturing/transmitting unauthorized images",
            "Rule 3(2)(b) IT Rules 2021: Mandatory removal within 24 hours of morphed/deepfake intimate content"
        ],
        "harassment": [
            "Section 354D IPC / Section 78 BNS: Stalking and electronic harassment of women",
            "Section 506 IPC / Section 351 BNS: Criminal intimidation and threats to cause bodily harm",
            "Section 509 IPC / Section 79 BNS: Words, gestures or acts intended to insult modesty of woman"
        ],
        "misuse": [
            "Section 43 & 66 IT Act: Unauthorized access, downloading, and exploitation of digital assets",
            "Section 79(3)(b) IT Act: Intermediary liability upon failure to expeditiously take down infringing content",
            "Copyright Act Section 51/52: Infringement of exclusive intellectual property rights"
        ],
        "threat": [
            "Section 506 IPC / Section 351 BNS: Threat of grievous hurt, death, or acid attack",
            "Section 66F IT Act: Cyber terrorism / extortion through electronic intimidation"
        ]
    }

    @classmethod
    def generate_complaint_ref_no(cls) -> str:
        """Generate unique legal complaint reference number."""
        token = secrets.token_hex(4).upper()
        return f"AEGIS-CMP-2026-{token}"

    @classmethod
    def generate_pseudonym_token(cls, user_id: int) -> str:
        """Generate anonymous victim reference identifier."""
        salt = secrets.token_hex(3).upper()
        return f"PROTECTED_COMPLAINANT_{salt}"

    @classmethod
    def file_confidential_complaint(
        cls,
        user_id: int,
        target_authority: str,
        incident_type: str,
        platform: str,
        violating_url: str,
        perpetrator_handle: str,
        is_confidential: bool = True,
        confidentiality_level: str = "Full Anonymity (Pseudonym)",
        relief_requested: str = "Immediate 24-Hour Content Takedown & Server IP Preservation",
        custom_statement: str = "",
        evidence_vault_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Creates a legally structured complaint petition while guaranteeing complainant confidentiality.
        """
        user = AuthService.get_user_by_id(user_id) or {}
        ref_no = cls.generate_complaint_ref_no()
        pseudonym = cls.generate_pseudonym_token(user_id)
        now = datetime.now().isoformat()

        # Select legal clauses
        clauses = cls.LEGAL_PROVISIONS.get(incident_type.lower(), cls.LEGAL_PROVISIONS["harassment"])

        # Confidentiality Handling
        if is_confidential:
            complainant_display = f"{pseudonym} (Victim Identity Protected under Section 72A IT Act / Section 73 BNS)"
            masked_email = "confidential-grievance-proxy@aegis.shield"
            masked_phone = "[SEALED CONFIDENTIAL INFORMATION]"
        else:
            complainant_display = user.get("full_name", "Complainant")
            masked_email = user.get("email", "")
            masked_phone = user.get("emergency_contact_phone", "")

        # Default formal statement if empty
        if not custom_statement:
            custom_statement = (
                f"This formal grievance is submitted regarding unlawful content originating on {platform} "
                f"at URL: {violating_url} authored by {perpetrator_handle or 'Unknown perpetrator'}. "
                f"The content constitutes unauthorized dissemination, digital harassment, or non-consensual "
                f"manipulation violating statutory provisions. Immediate takedown and evidence preservation are demanded."
            )

        # Cryptographic tamper seal
        seal_payload = f"{ref_no}:{target_authority}:{violating_url}:{now}"
        tamper_seal = sign_evidence_record(seal_payload)

        # Generate Official PDF Grievance Petition
        complaints_dir = EVIDENCE_DIR / str(user_id) / "complaints"
        complaints_dir.mkdir(parents=True, exist_ok=True)
        safe_plat = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in platform)
        pdf_path = str(complaints_dir / f"PETITION_{ref_no}_{safe_plat}.pdf")

        try:
            cls.generate_complaint_pdf(
                pdf_path=pdf_path,
                ref_no=ref_no,
                target_authority=target_authority,
                incident_type=incident_type,
                platform=platform,
                violating_url=violating_url,
                perpetrator_handle=perpetrator_handle,
                complainant_display=complainant_display,
                masked_email=masked_email,
                masked_phone=masked_phone,
                confidentiality_level=confidentiality_level,
                legal_clauses=clauses,
                relief_requested=relief_requested,
                statement=custom_statement,
                tamper_seal=tamper_seal,
                timestamp=now
            )
        except Exception as e:
            print(f"Error compiling complaint PDF: {e}")
            pdf_path = None

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO complaints (
                user_id, complaint_ref_no, target_authority, incident_type,
                platform, violating_url, perpetrator_handle, is_confidential,
                complainant_pseudonym, confidentiality_level, legal_clauses,
                relief_requested, complaint_statement, evidence_vault_id,
                tamper_seal_hash, pdf_complaint_path, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'drafted', ?)
            """, (
                user_id, ref_no, target_authority, incident_type,
                platform, violating_url, perpetrator_handle,
                1 if is_confidential else 0, pseudonym, confidentiality_level,
                json.dumps(clauses), relief_requested, custom_statement,
                evidence_vault_id, tamper_seal, pdf_path, now
            ))
            complaint_id = cursor.lastrowid

        log_audit_event(user_id, "CONFIDENTIAL_COMPLAINT_FILED", f"Ref={ref_no} Authority={target_authority} Confidential={is_confidential}")

        # Sync to Firebase Firestore collection 'confidential_complaints' (Privacy-Preserving)
        try:
            cloud_doc = {
                "complaint_ref_no": ref_no,
                "target_authority": target_authority,
                "incident_type": incident_type,
                "platform": platform,
                "violating_url": violating_url,
                "perpetrator_handle": perpetrator_handle or "@unknown",
                "is_confidential": is_confidential,
                "complainant_pseudonym": pseudonym,
                "confidentiality_level": confidentiality_level,
                "relief_requested": relief_requested,
                "tamper_seal_hash": tamper_seal,
                "status": "drafted",
                "created_at": now
            }
            FirebaseClient.save_document("confidential_complaints", ref_no, cloud_doc)
        except Exception as e:
            print(f"Firebase complaint sync error: {e}")

        return {
            "success": True,
            "complaint_id": complaint_id,
            "ref_no": ref_no,
            "pseudonym": pseudonym,
            "pdf_path": pdf_path,
            "tamper_seal": tamper_seal,
            "confidentiality_level": confidentiality_level
        }

    @classmethod
    def generate_complaint_pdf(
        cls,
        pdf_path: str,
        ref_no: str,
        target_authority: str,
        incident_type: str,
        platform: str,
        violating_url: str,
        perpetrator_handle: str,
        complainant_display: str,
        masked_email: str,
        masked_phone: str,
        confidentiality_level: str,
        legal_clauses: list,
        relief_requested: str,
        statement: str,
        tamper_seal: str,
        timestamp: str
    ):
        """Builds a formal, court-ready Confidential Legal Grievance Petition PDF."""
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter,
            rightMargin=36, leftMargin=36,
            topMargin=36, bottomMargin=36
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'PetitionTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=15,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=4
        )
        warning_style = ParagraphStyle(
            'WarnBanner',
            parent=styles['Normal'],
            fontName='Helvetica-Bold',
            fontSize=9,
            textColor=colors.HexColor('#991B1B'),
            leading=12
        )
        section_style = ParagraphStyle(
            'SecTitle',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=10,
            spaceAfter=4
        )
        text_style = ParagraphStyle(
            'Norm',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#334155'),
            leading=12
        )
        code_style = ParagraphStyle(
            'Code',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            textColor=colors.HexColor('#0F172A')
        )

        elements = []

        # 1. Statutory Victim Privacy Warning Banner
        warn_data = [[
            Paragraph(
                "<b>RESTRICTED LEGAL PRIVILEGE — VICTIM IDENTITY CONFIDENTIALITY NOTICE:</b><br/>"
                "This document is filed under mandatory statutory victim privacy protections (Section 72A IT Act, Section 73 BNS, "
                "and Rule 3(2) IT Rules 2021). Any unauthorized public disclosure or publication of complainant particulars is a cognizable criminal offense.",
                warning_style
            )
        ]]
        warn_table = Table(warn_data, colWidths=[540])
        warn_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FEE2E2')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#EF4444')),
            ('PADDING', (0, 0), (-1, -1), 8),
        ]))
        elements.append(warn_table)
        elements.append(Spacer(1, 12))

        # 2. Formal Petition Header
        elements.append(Paragraph(f"<b>FORMAL GRIEVANCE & STATUTORY TAKEDOWN REQUISITION</b>", title_style))
        elements.append(Paragraph(f"<b>Case Ref No:</b> <code>{ref_no}</code> | <b>Filing Timestamp:</b> {timestamp} (UTC)", text_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563EB'), spaceAfter=12))

        # 3. Addressed Authority & Complainant Particulars Table
        meta_table_data = [
            [Paragraph("<b>TO (RESPONDENT / RECIPIENT):</b>", text_style), Paragraph(f"<b>{target_authority}</b>", text_style)],
            [Paragraph("<b>COMPLAINANT IDENTITY:</b>", text_style), Paragraph(f"<b>{complainant_display}</b>", text_style)],
            [Paragraph("<b>CONFIDENTIALITY MODE:</b>", text_style), Paragraph(f"<b>{confidentiality_level}</b>", text_style)],
            [Paragraph("<b>CONTACT FOR LEGAL NOTICE:</b>", text_style), Paragraph(f"Email: {masked_email} | Phone: {masked_phone}", text_style)],
            [Paragraph("<b>VIOLATING PLATFORM:</b>", text_style), Paragraph(f"<b>{platform}</b>", text_style)],
            [Paragraph("<b>OFFENDING POST / CONTENT URL:</b>", text_style), Paragraph(f"<u>{violating_url}</u>", text_style)],
            [Paragraph("<b>PERPETRATOR USER / HANDLE:</b>", text_style), Paragraph(f"{perpetrator_handle or 'Unknown / Impersonator'}", text_style)],
            [Paragraph("<b>INCIDENT CLASSIFICATION:</b>", text_style), Paragraph(f"<b>{incident_type.upper()}</b>", text_style)],
        ]
        meta_table = Table(meta_table_data, colWidths=[160, 380])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        # 4. Statement of Facts & Grievance
        elements.append(Paragraph("<b>1. STATEMENT OF FACTS & UNLAWFUL ACTS</b>", section_style))
        elements.append(Paragraph(statement, text_style))
        elements.append(Spacer(1, 10))

        # 5. Applicable Legal Provisions & Statutory Mandates
        elements.append(Paragraph("<b>2. STATUTORY PROVISIONS & LEGAL MANDATES</b>", section_style))
        for clause in legal_clauses:
            elements.append(Paragraph(f"• {clause}", text_style))
        elements.append(Spacer(1, 10))

        # 6. Specific Relief Demanded
        elements.append(Paragraph("<b>3. SPECIFIC RELIEF DEMANDED</b>", section_style))
        relief_items = [
            f"<b>A. Expedited Takedown:</b> Immediately disable access to or remove the infringing content at the reported URL pursuant to 24-hour statutory requirements.",
            f"<b>B. Preservation of Server Records:</b> Preserve all access logs, IP addresses, device identifiers, and upload timestamps relating to the perpetrator account for investigation.",
            f"<b>C. Perpetrator Action:</b> Issue appropriate sanctions, suspensions, or initiate formal grievance redressal proceedings against the violating entity.",
            f"<b>D. Victim Safety Protection:</b> Ensure the complainant's real identity remains strictly sealed and unshared with the accused party."
        ]
        for r in relief_items:
            elements.append(Paragraph(r, text_style))
        elements.append(Spacer(1, 12))

        # 7. Verification Seal & Chain of Custody
        elements.append(Paragraph("<b>4. VERIFICATION & CRYPTOGRAPHIC SEAL</b>", section_style))
        seal_text = (
            f"This petition is cryptographically sealed by the <b>AEGIS Digital Safety Framework</b>. "
            f"Seal Digest: <code>{tamper_seal}</code>. The integrity and authenticity of the evidentiary links "
            f"embedded herein are verifiable under Section 65B of the Indian Evidence Act / IT Act."
        )
        elements.append(Paragraph(seal_text, text_style))

        doc.build(elements)

    @classmethod
    def get_user_complaints(cls, user_id: int) -> List[Dict[str, Any]]:
        """Retrieve all filed complaints for a user."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM complaints WHERE user_id = ? ORDER BY id DESC", (user_id,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["legal_clauses"] = json.loads(item["legal_clauses"])
                except Exception:
                    item["legal_clauses"] = []
                results.append(item)
            return results

    @classmethod
    def update_complaint_status(cls, complaint_id: int, user_id: int, new_status: str) -> bool:
        """Update complaint progress ('drafted', 'filed', 'under_investigation', 'resolved')."""
        with get_db() as conn:
            conn.execute(
                "UPDATE complaints SET status = ? WHERE id = ? AND user_id = ?",
                (new_status, complaint_id, user_id)
            )
        log_audit_event(user_id, "COMPLAINT_STATUS_UPDATED", f"Complaint ID={complaint_id} status={new_status}")
        return True
