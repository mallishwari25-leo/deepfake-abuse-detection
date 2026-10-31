"""
AEGIS-Social Unified 4-Tier Risk Classifier
Maps multi-modal signals into standard GREEN, YELLOW, ORANGE, and RED threat bands.
"""
from typing import Dict, Any
from backend.config import RISK_LEVELS


class UnifiedRiskClassifier:
    """
    Standardizes risk evaluation across visual media, deepfakes, and text harassment.
    """

    @staticmethod
    def classify_combined_risk(
        visual_similarity_score: float = 0.0,
        manipulation_score: float = 0.0,
        explicit_score: float = 0.0,
        nlp_risk_level: str = "GREEN",
        is_unauthorized_redistribution: bool = False
    ) -> Dict[str, Any]:
        """
        Synthesizes composite incident risk.
        Bands:
        - GREEN: Safe content
        - YELLOW: Potentially inappropriate language or suspicious content
        - ORANGE: Abusive language, harassment, or potentially manipulated media
        - RED: Serious threats, suspected intimate-image abuse, explicit content, or severe targeted harassment
        """
        # Start with base score
        severity_score = 0
        reasons = []

        # 1. Check severe RED triggers
        if nlp_risk_level == "RED":
            severity_score = max(severity_score, 3)
            reasons.append("Direct threats of violence, criminal extortion, or suicide incitement in text.")

        if explicit_score >= 0.70:
            severity_score = max(severity_score, 3)
            reasons.append("High probability of sexually explicit material or non-consensual intimate imagery exposure.")

        # 2. Check ORANGE triggers
        if nlp_risk_level == "ORANGE":
            severity_score = max(severity_score, 2)
            reasons.append("Abusive language, targeted cyberbullying, or hate speech.")

        if manipulation_score >= 0.60:
            severity_score = max(severity_score, 2)
            reasons.append("Suspected deepfake or digital facial tampering detected with elevated confidence.")

        if is_unauthorized_redistribution and visual_similarity_score >= 88.0:
            severity_score = max(severity_score, 2)
            reasons.append("High visual similarity match discovered on unlinked third-party public account.")

        # 3. Check YELLOW triggers
        if nlp_risk_level == "YELLOW":
            severity_score = max(severity_score, 1)
            reasons.append("Questionable language, derogatory comments, or body shaming.")

        if 0.40 <= manipulation_score < 0.60:
            severity_score = max(severity_score, 1)
            reasons.append("Moderate compression artifacts or edge gradient inconsistencies.")

        if 0.35 <= explicit_score < 0.70:
            severity_score = max(severity_score, 1)
            reasons.append("Partial skin exposure or sensitive context.")

        if is_unauthorized_redistribution and 75.0 <= visual_similarity_score < 88.0:
            severity_score = max(severity_score, 1)
            reasons.append("Moderate visual resemblance to user's protected reference media.")

        # Map to label
        level_map = {0: "GREEN", 1: "YELLOW", 2: "ORANGE", 3: "RED"}
        final_level = level_map.get(severity_score, "GREEN")
        meta = RISK_LEVELS[final_level]

        # Calculate confidence
        if final_level == "RED":
            confidence = 94.0 + min(5.0, len(reasons) * 1.5)
        elif final_level == "ORANGE":
            confidence = 86.0 + min(10.0, len(reasons) * 2.0)
        elif final_level == "YELLOW":
            confidence = 78.0 + min(12.0, len(reasons) * 3.0)
        else:
            confidence = 96.0
            reasons = ["Content exhibits standard benign signatures; no threat or abuse triggers identified."]

        return {
            "risk_level": final_level,
            "badge": meta["badge"],
            "color": meta["color"],
            "name": meta["name"],
            "confidence_score": round(confidence, 1),
            "reasons": reasons,
            "summary_explanation": " ".join(reasons)
        }
