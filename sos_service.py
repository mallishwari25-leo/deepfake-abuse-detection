"""
AEGIS-Social SOS & Emergency Support Service
Provides cybercrime reporting guidance, platform-direct complaint links,
emergency helplines, and rapid safety action checklists.
Strict Rule: NEVER automatically reports or messages perpetrators without explicit authorization.
"""
from typing import Dict, Any, List


class SOSSupportService:
    """Delivers emergency cyber-safety resources and structured escalation workflows."""

    EMERGENCY_DIRECTORIES = {
        "India": {
            "cybercrime_portal": "https://cybercrime.gov.in",
            "cybercrime_portal_name": "National Cyber Crime Reporting Portal (cybercrime.gov.in)",
            "national_helpline": "1930",
            "national_helpline_desc": "National Cyber Financial & Harassment Helpline (MHA)",
            "police_emergency": "112",
            "ncw_helpline": "7827170170",
            "ncw_desc": "National Commission for Women (NCW) Cyber Cell Helpline",
            "childline": "1098"
        },
        "United States": {
            "cybercrime_portal": "https://www.ic3.gov",
            "cybercrime_portal_name": "FBI Internet Crime Complaint Center (IC3)",
            "national_helpline": "988",
            "national_helpline_desc": "Suicide & Crisis Lifeline (Confidential)",
            "police_emergency": "911",
            "cybertip_line": "https://report.cybertip.org"
        },
        "Global": {
            "stop_ncii": "https://stopncii.org",
            "stop_ncii_name": "StopNCII.org (Prevent Non-Consensual Intimate Image Sharing)",
            "take_it_down": "https://takeitdown.ncmec.org",
            "take_it_down_name": "Take It Down (NCMEC - Intimate imagery removal for under 18s)",
            "access_now": "https://www.accessnow.org/help/",
            "access_now_desc": "Digital Security Helpline (24/7 Civil Society Protection)"
        }
    }

    PLATFORM_REPORTING_LINKS = [
        {
            "platform": "Instagram",
            "icon": "📸",
            "issue": "Harassment, Bullying & Impersonation",
            "direct_url": "https://help.instagram.com/547601325292351",
            "action_guidance": "Select 'Report' on post/profile > 'It's inappropriate' > 'Bullying or harassment'."
        },
        {
            "platform": "X / Twitter",
            "icon": "🐦",
            "issue": "Abusive Behavior, Threats & Hateful Conduct",
            "direct_url": "https://help.twitter.com/en/safety-and-security/report-abusive-behavior",
            "action_guidance": "Click the three dots (...) on post > 'Report post' > 'Attack on me or someone else'."
        },
        {
            "platform": "YouTube",
            "icon": "▶️",
            "issue": "Cyberbullying & Defamatory Content",
            "direct_url": "https://support.google.com/youtube/answer/2802268",
            "action_guidance": "Click '...' under video > 'Report' > 'Harassment or cyberbullying'."
        },
        {
            "platform": "Reddit",
            "icon": "🤖",
            "issue": "Targeted Harassment & Doxxing",
            "direct_url": "https://www.reddit.com/report",
            "action_guidance": "Select 'I want to report other issues' > 'Harassment' or 'Sharing personal information'."
        },
        {
            "platform": "Facebook",
            "icon": "👥",
            "issue": "Unauthorized Sharing & Harassment",
            "direct_url": "https://www.facebook.com/help/181495968648557",
            "action_guidance": "Find post > Click '...' > 'Report post' > 'Harassment'."
        },
        {
            "platform": "Telegram",
            "icon": "✈️",
            "issue": "Illegal Content & Explicit Abuse",
            "direct_url": "https://telegram.org/faq#q-there-is-illegal-content-on-telegram-how-do-i-take-it-down",
            "action_guidance": "Forward public post to @notoscam or email abuse@telegram.org."
        }
    ]

    @classmethod
    def get_emergency_info(cls, country: str = "India") -> Dict[str, Any]:
        """Fetch localized helplines and global protection links."""
        local = cls.EMERGENCY_DIRECTORIES.get(country, cls.EMERGENCY_DIRECTORIES["India"])
        global_res = cls.EMERGENCY_DIRECTORIES["Global"]
        return {
            "country": country,
            "local_resources": local,
            "global_resources": global_res,
            "platform_links": cls.PLATFORM_REPORTING_LINKS
        }

    @classmethod
    def generate_emergency_contact_draft(
        cls,
        user_name: str,
        emergency_contact_name: str,
        incident_platform: str,
        incident_type: str,
        severity_level: str
    ) -> str:
        """Create a clear SOS notification message ready for user to send."""
        return (
            f"URGENT SAFETY ALERT: Hi {emergency_contact_name}, this is {user_name}. "
            f"My digital safety monitor AEGIS has detected a {severity_level} threat incident "
            f"involving {incident_type} on {incident_platform}. "
            f"Evidence has been securely preserved. I may need assistance or to coordinate with cyber authorities. "
            f"Please reach out to me as soon as you receive this."
        )

    @classmethod
    def get_lockdown_checklist(cls) -> List[Dict[str, str]]:
        """Instant personal cyber-defense checklist."""
        return [
            {
                "step": "1. Set Accounts to Private",
                "detail": "Immediately switch Instagram, X, and Facebook privacy settings to 'Private / Followers Only' to halt scraping."
            },
            {
                "step": "2. Enable Two-Factor Authentication (2FA)",
                "detail": "Activate Authenticator App (TOTP) or Security Key 2FA on all linked social email and accounts."
            },
            {
                "step": "3. Do Not Engage With Perpetrators",
                "detail": "Avoid replying to threatening or baiting comments. Responses can escalate coordinated attacks."
            },
            {
                "step": "4. Preserve Digital Evidence",
                "detail": "Click 'Preserve to Evidence Vault' in AEGIS to capture tamper-evident PDF dossiers before content is deleted."
            },
            {
                "step": "5. File Grievance with National Cyber Portal",
                "detail": "Submit official complaint at cybercrime.gov.in or dial 1930 (in India) or IC3.gov (in US) attaching the AEGIS dossier."
            }
        ]
