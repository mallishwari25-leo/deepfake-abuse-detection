"""
AEGIS-Social Image Misuse & Redistribution Matcher
Performs multi-hash perceptual image matching against authorized social media repositories.
Explicitly distinguishes real API scans from benchmark simulation feeds.
"""
from typing import List, Dict, Any, Optional
from PIL import Image
from backend.ai_engine.fingerprinting import MediaFingerprinter
from backend.ai_engine.deepfake_detector import DeepfakeDetector
from backend.ai_engine.risk_classifier import UnifiedRiskClassifier


class SocialMediaImageMatcher:
    """
    Scans public and authorized sources for potentially matching media.
    Calculates multi-hash similarity and forensic tampering metrics.
    """

    @classmethod
    def compare_media(
        cls,
        target_fingerprint: dict,
        candidate_image: Image.Image,
        candidate_metadata: dict
    ) -> Dict[str, Any]:
        """
        Compare an uploaded target media fingerprint against a candidate post image.
        """
        # Fingerprint candidate
        candidate_fp = MediaFingerprinter.fingerprint_image(candidate_image)

        # Multi-hash similarity
        similarity_score = MediaFingerprinter.compute_composite_similarity(
            target_fingerprint,
            candidate_fp
        )

        # Deepfake forensic scan on candidate
        forensics = DeepfakeDetector.analyze_image(candidate_image)

        # Risk evaluation
        is_unauthorized = candidate_metadata.get("is_authorized_account", False) is False
        risk_eval = UnifiedRiskClassifier.classify_combined_risk(
            visual_similarity_score=similarity_score,
            manipulation_score=forensics["composite_score"],
            is_unauthorized_redistribution=is_unauthorized and similarity_score >= 75.0
        )

        return {
            "source_platform": candidate_metadata.get("platform", "Unknown"),
            "source_handle": candidate_metadata.get("handle", "@unknown"),
            "post_url": candidate_metadata.get("post_url", "https://example.com/post"),
            "similarity_score": similarity_score,
            "match_confidence": round(min(99.0, max(similarity_score, forensics["confidence_score"])), 1),
            "risk_level": risk_eval["risk_level"],
            "risk_badge": risk_eval["badge"],
            "risk_explanation": risk_eval["summary_explanation"],
            "is_manipulated": forensics["is_manipulated"],
            "manipulation_score": forensics["composite_score"],
            "manipulation_details": forensics["explanation"],
            "forensics": forensics,
            "is_simulated": candidate_metadata.get("is_simulated", False),
            "disclaimer": "IMPORTANT: Visual similarity indicates statistical resemblance and does not constitute definitive proof of unauthorized copyright infringement or misuse."
        }
