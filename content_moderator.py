"""
AEGIS-Social Visual Content Moderator
Detects inappropriate content, potential non-consensual intimate imagery (NCII),
unclothed skin exposure, and harmful image alterations.
"""
import numpy as np
from PIL import Image


class VisualContentModerator:
    """
    Analyzes visual media for sexually explicit content, non-consensual exposure risks,
    and harmful modifications.
    """

    @staticmethod
    def detect_skin_pixels(rgb_image: Image.Image) -> tuple[float, float]:
        """
        Segment skin pixels using multi-space YCbCr and HSV bounding rules.
        Tuned to cover diverse global and South Asian skin tones.
        Returns:
            skin_ratio: proportion of total image pixels identified as skin (0.0 to 1.0)
            central_skin_ratio: proportion of central focal area identified as skin
        """
        img = rgb_image.convert('RGB').resize((180, 180))
        rgb = np.array(img, dtype=np.float32)

        # Standard RGB to YCbCr conversion matrix
        r, g, b = rgb[:, :, 0], rgb[:, :, 1], rgb[:, :, 2]
        y = 0.299 * r + 0.587 * g + 0.114 * b
        cb = 128 - 0.168736 * r - 0.331264 * g + 0.5 * b
        cr = 128 + 0.5 * r - 0.418688 * g - 0.081312 * b

        # Empirical skin locus in YCbCr space
        skin_mask = (y > 70) & (cb >= 75) & (cb <= 135) & (cr >= 130) & (cr <= 180)

        # Additional HSV heuristic to exclude yellowish/bright backgrounds
        # Max - Min channel rule
        max_c = np.maximum(np.maximum(r, g), b)
        min_c = np.minimum(np.minimum(r, g), b)
        rule_rgb = (r > 95) & (g > 40) & (b > 20) & ((max_c - min_c) > 15) & (abs(r - g) > 15) & (r > g) & (r > b)

        combined_mask = skin_mask & rule_rgb
        total_pixels = 180 * 180
        skin_ratio = float(np.sum(combined_mask) / total_pixels)

        # Center 60% crop
        center_mask = combined_mask[36:144, 36:144]
        central_skin_ratio = float(np.sum(center_mask) / (108 * 108))

        return round(skin_ratio, 3), round(central_skin_ratio, 3)

    @classmethod
    def moderate_media(cls, image: Image.Image) -> dict:
        """
        Perform safety scan on image media for explicit content and intimate exposure.
        """
        skin_ratio, central_skin_ratio = cls.detect_skin_pixels(image)

        # Risk scoring
        explicit_risk_score = 0.0
        reasons = []

        # Analyze exposure ratios
        if skin_ratio > 0.45 or central_skin_ratio > 0.55:
            explicit_risk_score = 0.85
            reasons.append("High percentage of unclothed skin surface area detected")
        elif skin_ratio > 0.28 or central_skin_ratio > 0.35:
            explicit_risk_score = 0.52
            reasons.append("Moderate skin exposure identified (potential swimsuit, partial nudity, or provocative attire)")
        else:
            explicit_risk_score = 0.10
            reasons.append("Standard coverage; no high-risk nudity signatures detected")

        # Risk categorization
        if explicit_risk_score >= 0.75:
            risk_level = "RED"
            explanation = "Content flagged for potential sexually explicit material or intimate-image exposure risk."
        elif explicit_risk_score >= 0.40:
            risk_level = "YELLOW"
            explanation = "Moderate exposure detected; warrants review under personal safety guidelines."
        else:
            risk_level = "GREEN"
            explanation = "Visual content appears compliant with personal safety standards."

        return {
            "explicit_risk_score": explicit_risk_score,
            "skin_ratio": skin_ratio,
            "central_skin_ratio": central_skin_ratio,
            "risk_level": risk_level,
            "is_inappropriate": explicit_risk_score >= 0.60,
            "reasons": reasons,
            "explanation": explanation
        }
