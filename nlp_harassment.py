"""
AEGIS-Social Multilingual Harassment & Abuse Detection Engine
Supports English, Hindi, Telugu, Tamil, and Romanized code-mixed variants (Hinglish, Tenglish, Tanglish).
Handles leetspeak, spelling distortions, slang, and context-aware severity scoring.
"""
import re
import unicodedata
from typing import Dict, List, Any


class MultilingualHarassmentDetector:
    """
    Identifies 10 core safety categories:
    1. Vulgar & sexually inappropriate language
    2. Personal insults and humiliation
    3. Cyberbullying
    4. Threatening language / physical violence
    5. Harassment and intimidation
    6. Body shaming
    7. Gender-based abusive language
    8. Hate speech
    9. Targeted harassment
    10. Attempts to publicly shame or defame
    """

    # Leetspeak and symbol de-obfuscation map
    LEET_MAP = {
        '@': 'a', '4': 'a', '8': 'b', '(': 'c', '<': 'c', '3': 'e',
        '1': 'i', '!': 'i', '|': 'i', '0': 'o', '$': 's', '5': 's',
        '7': 't', '+': 't', 'v': 'v', 'w': 'w', '*': '', '_': ' '
    }

    # Multilingual Lexicons with category tags & severity weights (1 to 4)
    ABUSE_PATTERNS = [
        # --- 1. THREATS & VIOLENCE (SEVERITY 4 -> RED) ---
        (r"\b(kill|murder|shoot|stab|slit|burn|hang|execute)\s+(you|u|ur|yourself)\b", ["threat_violence"], 4, "Direct death or severe violent threat directed at the user."),
        (r"\b(i\s*will\s*(find|track|hunt|kill|end|destroy)\s*(you|u))\b", ["threat_violence", "harassment_intimidation"], 4, "Explicit stalking or threat of physical harm."),
        (r"\b(acid\s*attack|throw\s*acid)\b", ["threat_violence", "gender_abuse"], 4, "Acid attack threat (severe criminal violence under IPC/BNS)."),
        (r"\b(doxx|doxxing|leak\s*your\s*address|leak\s*your\s*phone|leak\s*your\s*number)\b", ["threat_violence", "harassment_intimidation"], 4, "Doxxing threat involving personal privacy breach."),
        (r"\b(go\s*die|kill\s*yourself|kys|drink\s*poison|hang\s*yourself)\b", ["threat_violence", "cyberbullying"], 4, "Suicide incitement and extreme cyberbullying."),

        # Hindi / Hinglish Threats
        (r"\b(jaan\s*se\s*maar\s*(dunga|denge|dalenge)|goli\s*maar|gala\s*kaat)\b", ["threat_violence"], 4, "Direct death threat in Hindi (जान से मार दूंगा)."),
        (r"\b(mar\s*ja|jaake\s*mar|zeher\s*khaa|latak\s*ja)\b", ["threat_violence", "cyberbullying"], 4, "Suicide encouragement in Hindi."),
        (r"\b(tujhe\s*dekh\s*loonga|tere\s*ghar\s*aake\s*peetunga|ghar\s*pe\s*aake)\b", ["threat_violence", "harassment_intimidation"], 4, "Physical threat and intimidation in Hindi."),

        # Telugu / Tenglish Threats
        (r"\b(champestha|champesthamu|kosi\s*karam|narikestha|ninnu\s*champesta)\b", ["threat_violence"], 4, "Direct death threat in Telugu (చంపేస్తా / violent harm)."),
        (r"\b(poyi\s*chavu|visham\s*taagu|uri\s*vesuko)\b", ["threat_violence", "cyberbullying"], 4, "Suicide incitement in Telugu."),
        (r"\b(nee\s*intiki\s*vachi\s*kadata|ninnu\s*vadalanu)\b", ["threat_violence", "harassment_intimidation"], 4, "Physical confrontation threat in Telugu."),

        # Tamil / Tanglish Threats
        (r"\b(kolla\s*poren|kolluven|vettiruven|adichu\s*kolluven|sava\s*adi)\b", ["threat_violence"], 4, "Direct murder threat in Tamil (கொல்லப் போறேன்)."),
        (r"\b(poi\s*saavu|visham\s*kudi|thooku\s*maattiko)\b", ["threat_violence", "cyberbullying"], 4, "Suicide incitement in Tamil."),
        (r"\b(unna\s*summa\s*vida\s*maatten|veetukku\s*vandhu)\b", ["threat_violence", "harassment_intimidation"], 4, "Physical intimidation in Tamil."),

        # --- 2. VULGAR, SEXUALLY INAPPROPRIATE & INTIMATE ABUSE (SEVERITY 4 -> RED / ORANGE) ---
        (r"\b(send\s*nudes|send\s*nude|nude\s*pics|boobs|pussy|dick\s*pic|send\s*mms)\b", ["vulgar_sexual"], 3, "Unsolicited sexual solicitation or intimate image demand."),
        (r"\b(leaked\s*mms|viral\s*video|private\s*video\s*leaked|deepfake\s*nude|hot\s*clip\s*leaked)\b", ["vulgar_sexual", "defamation_shaming"], 4, "Intimate-image blackmail, non-consensual explicit material leak attempt."),
        (r"\b(slut|whore|bitch|skank|hooker|prostitute|cunt)\b", ["gender_abuse", "vulgar_sexual"], 3, "Misogynistic and sexually abusive slurs."),

        # Hindi / Hinglish Sexual & Vulgar
        (r"\b(randi|chutiya|bhadwe|harami|bhosdike|bhosadi|madarchod|behenchod|gaand|lund|choot|chinaal)\b", ["vulgar_sexual", "gender_abuse"], 3, "Vulgar and sexually abusive slurs in Hindi/Hinglish."),
        (r"\b(rate\s*bata|kitne\s*me\s*chalegi|bistar\s*me)\b", ["vulgar_sexual", "harassment_intimidation"], 4, "Sexual solicitation and degrading exploitation in Hindi."),

        # Telugu / Tenglish Sexual & Vulgar
        (r"\b(lanja|donga\s*lanja|lanjakodaka|guddha|puku|modda|lanja\s*munda|bevarse)\b", ["vulgar_sexual", "gender_abuse"], 3, "Vulgar and sexually abusive slurs in Telugu/Tenglish."),
        (r"\b(entha\s*teesukuntav|reyt\s*entha|okkarathriki)\b", ["vulgar_sexual", "harassment_intimidation"], 4, "Sexual solicitation and degrading harassment in Telugu."),

        # Tamil / Tanglish Sexual & Vulgar
        (r"\b(thevidiya|thevidya|thevidiya\s*payale|sunni|oombu|pundai|poolu|kena\s*pundai)\b", ["vulgar_sexual", "gender_abuse"], 3, "Vulgar and sexually abusive slurs in Tamil/Tanglish."),
        (r"\b(evalo\s*rate|oru\s*night\s*ku\s*varuva)\b", ["vulgar_sexual", "harassment_intimidation"], 4, "Sexual solicitation and degrading abuse in Tamil."),

        # --- 3. PERSONAL INSULTS, HUMILIATION & CYBERBULLYING (SEVERITY 2 -> YELLOW / ORANGE) ---
        (r"\b(worthless|loser|disgusting|pathetic|garbage|scum|ugly|dumb|idiot|clown|stupid|moron)\b", ["personal_insult", "cyberbullying"], 2, "Derogatory personal insult and humiliation."),
        (r"\b(nobody\s*likes\s*you|everyone\s*hates\s*you|waste\s*of\s*space|waste\s*of\s*oxygen)\b", ["cyberbullying", "personal_insult"], 2, "Psychological cyberbullying and exclusion."),
        (r"\b(pagal|kutta|kamina|ullu\s*ke\s*patthe|gadha|jahil|neech|badtameez)\b", ["personal_insult"], 2, "Personal insults and disparagement in Hindi."),
        (r"\b(erri\s*pooku|chetha\s*na\s*kodaka|dhed\s*dimak|pichoda|vedhava|chettha)\b", ["personal_insult"], 2, "Personal insults and humiliation in Telugu."),
        (r"\b(porukki|loosu|muttaal|venna|thiruttu|panri|naaye|kirukku)\b", ["personal_insult"], 2, "Personal insults and verbal abuse in Tamil."),

        # --- 4. BODY SHAMING (SEVERITY 2 -> YELLOW / ORANGE) ---
        (r"\b(fat\s*pig|fat\s*cow|whale|ugly\s*face|anorexic|skinny\s*skeleton|elephant|so\s*fat|lose\s*weight)\b", ["body_shaming"], 2, "Body shaming and appearance-based mockery."),
        (r"\b(moti\s*bhains|motu|kaali|kaala\s*kauwa|bhootni|chudail)\b", ["body_shaming", "gender_abuse"], 2, "Body shaming, colorism, and appearance insult in Hindi."),
        (r"\b(laavuga\s*unnav|gundu\s*danne|kari\s*moham|nalloda|potti)\b", ["body_shaming"], 2, "Body shaming and skin tone disparagement in Telugu."),
        (r"\b(gundu\s*pandri|karuppi|asingama\s*irukka|kariya\s*mooji)\b", ["body_shaming"], 2, "Body shaming and colorist abuse in Tamil."),

        # --- 5. DEFAMATION, PUBLIC SHAMING & EXTORTION (SEVERITY 3 -> ORANGE / RED) ---
        (r"\b(i\s*will\s*(expose|ruin|cancel|defame)\s*you|fraud|cheater|scammer|criminal|thief)\b", ["defamation_shaming", "harassment_intimidation"], 3, "Attempt to publicly defame, blackmail, or orchestrate smear campaign."),
        (r"\b(blackmail|pay\s*me\s*or\s*else|give\s*money\s*or\s*i\s*leak|send\s*money)\b", ["defamation_shaming", "threat_violence"], 4, "Financial extortion and digital blackmail."),
        (r"\b(sabke\s*saamne\s*expose\s*karunga|barbaad\s*kar\s*dunga|tera\s*asli\s*chehra)\b", ["defamation_shaming"], 3, "Public shaming and smear threats in Hindi."),
        (r"\b(antha\s*mandhilo\s*paruvu\s*theesta|motham\s*bayata\s*pedatha|donga)\b", ["defamation_shaming"], 3, "Defamation and exposure threat in Telugu."),
        (r"\b(ellarkum\s*kaata\s*poren|maanatha\s*vaanga\s*poren|fraud\s*pannitta)\b", ["defamation_shaming"], 3, "Public shaming and defamation threat in Tamil."),

        # --- 6. HATE SPEECH & TARGETED HARASSMENT (SEVERITY 3 -> ORANGE / RED) ---
        (r"\b(terrorist|go\s*back\s*to\s*your\s*country|anti\s*national|dalit\s*slur|casteist|mulle|jihadi|infidel)\b", ["hate_speech"], 3, "Communal, religious, or caste-based hate speech."),
        (r"\b(mass\s*report\s*this\s*account|let['s\s]*destroy\s*this\s*account|everyone\s*spam)\b", ["targeted_harassment", "cyberbullying"], 3, "Coordinated brigade and targeted mass harassment campaign.")
    ]

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """
        De-obfuscate text: replaces leetspeak, collapses repeated characters (e.g. kuuutttaaa -> kutta),
        converts unicode to standard NFKD, and lowercases.
        """
        if not text:
            return ""

        # Normalize unicode accents
        normalized = unicodedata.normalize('NFKD', text)

        # Lowercase
        lowered = normalized.lower()

        # Substitute leetspeak chars
        for char, sub in cls.LEET_MAP.items():
            lowered = lowered.replace(char, sub)

        # Collapse excessive repeating characters (e.g., 'sooooo bad' -> 'soo bad')
        lowered = re.sub(r'(.)\1{2,}', r'\1\1', lowered)

        return lowered

    @classmethod
    def detect_language(cls, text: str) -> str:
        """
        Identify predominant script or language clues.
        Supports English, Hindi (Devanagari / Hinglish), Telugu (Telugu / Tenglish), Tamil (Tamil / Tanglish).
        """
        devanagari_count = len(re.findall(r'[\u0900-\u097F]', text))
        telugu_count = len(re.findall(r'[\u0C00-\u0C7F]', text))
        tamil_count = len(re.findall(r'[\u0B80-\u0BFF]', text))

        if devanagari_count >= 2:
            return "Hindi (Devanagari)"
        if telugu_count >= 2:
            return "Telugu (తెలుగు)"
        if tamil_count >= 2:
            return "Tamil (தமிழ்)"

        # Check Romanized phonetic markers
        norm = text.lower()
        if any(w in norm for w in ["kutta", "chutiya", "randi", "bhosdike", "maar dunga", "madarchod", "hai", "karo", "tujhe"]):
            return "Hinglish (Code-Mixed)"
        if any(w in norm for w in ["lanja", "champestha", "puku", "modda", "chetha", "kodaka", "unnav", "enti", "chesta"]):
            return "Tenglish (Code-Mixed)"
        if any(w in norm for w in ["thevidiya", "kolluven", "pundai", "sunni", "irukka", "panri", "naaye", "poren"]):
            return "Tanglish (Code-Mixed)"

        return "English"

    @classmethod
    def analyze_text(cls, text: str) -> Dict[str, Any]:
        """
        Scan text against abusive categories, evaluate context, and return risk classification.
        """
        if not text or not text.strip():
            return {
                "risk_level": "GREEN",
                "confidence_score": 98.0,
                "categories": [],
                "detected_language": "Unknown",
                "explanation": "No text content provided.",
                "matched_terms": []
            }

        norm_text = cls.normalize_text(text)
        detected_lang = cls.detect_language(text)

        matched_categories = set()
        matched_explanations = []
        max_severity = 1
        matched_snippets = []

        for pattern, cats, severity, exp in cls.ABUSE_PATTERNS:
            match = re.search(pattern, norm_text, re.IGNORECASE)
            if match:
                matched_categories.update(cats)
                matched_explanations.append(exp)
                matched_snippets.append(match.group(0))
                if severity > max_severity:
                    max_severity = severity

        cat_list = sorted(list(matched_categories))

        # Risk level determination based on highest severity and category count
        if max_severity >= 4:
            risk_level = "RED"
            confidence = 94.0 + min(5.0, len(cat_list) * 1.5)
            summary = "CRITICAL: Severe threat of violence, suicide incitement, or intimate extortion detected."
        elif max_severity == 3:
            risk_level = "ORANGE"
            confidence = 88.0 + min(8.0, len(cat_list) * 2.0)
            summary = "ELEVATED: Abusive language, targeted harassment, or explicit vulgar slurs identified."
        elif max_severity == 2:
            risk_level = "YELLOW"
            confidence = 82.0 + min(10.0, len(cat_list) * 2.5)
            summary = "CAUTION: Potentially inappropriate language, personal insults, or body shaming detected."
        else:
            risk_level = "GREEN"
            confidence = 96.5
            summary = "SAFE: No harassment, threats, or vulgar language detected."

        full_explanation = f"{summary} " + " ".join(matched_explanations[:2]) if matched_explanations else summary

        return {
            "risk_level": risk_level,
            "confidence_score": round(confidence, 1),
            "categories": cat_list,
            "detected_language": detected_lang,
            "explanation": full_explanation,
            "matched_terms": matched_snippets[:5],
            "is_toxic": max_severity >= 2
        }
