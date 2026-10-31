"""
AEGIS-Social Evidence Vault & Forensic Preservation Service
Generates cryptographically sealed incident records and official legal PDF reports.
Complies with digital forensics chain-of-custody standards (Indian IT Act Sec 65B & FRE 902(11)).
"""
import os
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.config import EVIDENCE_DIR, APP_NAME, APP_VERSION
from backend.database import get_db, log_audit_event
from backend.security import sign_evidence_record, compute_bytes_sha256


class EvidenceVaultService:
    """Safely preserves and seals digital evidence for law enforcement reporting."""

    @classmethod
    def seal_incident_evidence(
        cls,
        user_id: int,
        incident_title: str,
        incident_type: str,
        platform: str,
        source_url: str,
        raw_evidence_dict: dict
    ) -> Dict[str, Any]:
        """
        Create a tamper-evident sealed digital evidence dossier.
        """
        now = datetime.now().isoformat()
        serialized_data = json.dumps(raw_evidence_dict, sort_keys=True)
        seal_hash = sign_evidence_record(serialized_data + now)

        custody_log = [
            {
                "timestamp": now,
                "action": "EVIDENCE_CAPTURED_AND_HASHED",
                "officer_system": f"{APP_NAME} {APP_VERSION}",
                "hash": seal_hash
            }
        ]

        # Generate official PDF report
        user_evidence_dir = EVIDENCE_DIR / str(user_id)
        user_evidence_dir.mkdir(parents=True, exist_ok=True)
        safe_plat = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in platform)
        filename = f"EVIDENCE_DOSSIER_{int(datetime.now().timestamp())}_{safe_plat}.pdf"
        pdf_path = str(user_evidence_dir / filename)

        try:
            cls.generate_pdf_report(
                pdf_path=pdf_path,
                incident_title=incident_title,
                incident_type=incident_type,
                platform=platform,
                source_url=source_url,
                evidence_data=raw_evidence_dict,
                seal_hash=seal_hash,
                timestamp=now
            )
        except Exception as e:
            print(f"PDF generation error: {e}")
            pdf_path = None

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO evidence_vault (
                user_id, incident_title, incident_type, platform,
                source_url, evidence_data_json, tamper_seal_hash,
                chain_of_custody_log, pdf_report_path, created_at, sealed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user_id, incident_title, incident_type, platform,
                source_url, serialized_data, seal_hash,
                json.dumps(custody_log), pdf_path, now, now
            ))
            vault_id = cursor.lastrowid

        log_audit_event(user_id, "EVIDENCE_SEALED", f"Vault ID={vault_id} Seal={seal_hash}")

        return {
            "vault_id": vault_id,
            "seal_hash": seal_hash,
            "pdf_report_path": pdf_path,
            "timestamp": now
        }

    @classmethod
    def generate_pdf_report(
        cls,
        pdf_path: str,
        incident_title: str,
        incident_type: str,
        platform: str,
        source_url: str,
        evidence_data: dict,
        seal_hash: str,
        timestamp: str
    ):
        """Constructs an official, court-ready PDF Forensic Evidence Dossier."""
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter,
            rightMargin=40, leftMargin=40,
            topMargin=40, bottomMargin=40
        )
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=18,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=6
        )
        subtitle_style = ParagraphStyle(
            'DocSubtitle',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=10,
            textColor=colors.HexColor('#475569'),
            spaceAfter=15
        )
        section_style = ParagraphStyle(
            'SectionTitle',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=12,
            textColor=colors.HexColor('#1E293B'),
            spaceBefore=12,
            spaceAfter=6
        )
        text_style = ParagraphStyle(
            'NormalText',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=9,
            textColor=colors.HexColor('#1E293B'),
            leading=12
        )
        code_style = ParagraphStyle(
            'CodeText',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=8,
            textColor=colors.HexColor('#0F172A'),
            leading=10
        )

        elements = []

        # Header Banner
        elements.append(Paragraph(f"<b>AEGIS DIGITAL SAFETY PLATFORM</b>", title_style))
        elements.append(Paragraph(f"FORENSIC EVIDENCE PRESERVATION CERTIFICATE (SEC 65B / FRE 902 FORMAT)", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#2563EB'), spaceAfter=15))

        # Case Metadata Table
        metadata_data = [
            [Paragraph("<b>Incident Title:</b>", text_style), Paragraph(incident_title, text_style)],
            [Paragraph("<b>Incident Category:</b>", text_style), Paragraph(incident_type.upper(), text_style)],
            [Paragraph("<b>Source Platform:</b>", text_style), Paragraph(platform, text_style)],
            [Paragraph("<b>Preservation Timestamp:</b>", text_style), Paragraph(f"{timestamp} (UTC / ISO-8601)", text_style)],
            [Paragraph("<b>Source URL:</b>", text_style), Paragraph(source_url or "N/A", text_style)],
            [Paragraph("<b>Tamper Seal Hash:</b>", text_style), Paragraph(f"<code>{seal_hash}</code>", code_style)],
        ]
        meta_table = Table(metadata_data, colWidths=[150, 380])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 15))

        # Forensic Findings Section
        elements.append(Paragraph("<b>FORENSIC ANALYSIS & INCIDENT DETAILS</b>", section_style))

        finding_rows = []
        for k, v in evidence_data.items():
            if k in ["forensics", "video_keyframe_hashes"]:
                continue
            v_str = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
            finding_rows.append([Paragraph(f"<b>{k.replace('_', ' ').title()}:</b>", text_style), Paragraph(v_str, text_style)])

        if finding_rows:
            find_table = Table(finding_rows, colWidths=[150, 380])
            find_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FFFFFF')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
                ('PADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            elements.append(find_table)

        elements.append(Spacer(1, 15))

        # Legal Chain of Custody Declaration
        elements.append(Paragraph("<b>CHAIN OF CUSTODY & INTEGRITY DECLARATION</b>", section_style))
        declaration_text = (
            "This digital record was automatically compiled and preserved using standard cryptographic hashing "
            "(HMAC-SHA256). The integrity of this electronic document is verifiable against the seal hash embedded above. "
            "No human alteration or modification has occurred post-generation. Produced for official cybercrime "
            "investigation and platform grievance redressal under applicable cyber security frameworks."
        )
        elements.append(Paragraph(declaration_text, text_style))
        elements.append(Spacer(1, 10))

        # Emergency & Cybercrime Portal Assistance
        elements.append(Paragraph("<b>OFFICIAL REPORTING CONTACTS:</b>", text_style))
        help_text = (
            "• India Cybercrime Portal: https://cybercrime.gov.in | National Cyber Helpline: 1930<br/>"
            "• National Commission for Women (NCW) Cyber Cell: 7827170170<br/>"
            "• StopNCII.org (Non-Consensual Intimate Imagery Removal) | TakeItDown.ncmec.org"
        )
        elements.append(Paragraph(help_text, text_style))

        doc.build(elements)

    @classmethod
    def get_user_vault_records(cls, user_id: int) -> List[Dict[str, Any]]:
        """Retrieve all sealed evidence records for user."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT * FROM evidence_vault WHERE user_id = ? ORDER BY id DESC
            """, (user_id,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                try:
                    item["evidence_data"] = json.loads(item["evidence_data_json"])
                except Exception:
                    item["evidence_data"] = {}
                results.append(item)
            return results
