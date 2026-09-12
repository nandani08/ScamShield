import re
import logging
from typing import List, Dict, Any, Tuple, Optional, Set

logger = logging.getLogger("ArrestShield.ThreatPostProcessor")

# Common Indian Payment Service Provider (PSP) handles for UPI validation
VALID_UPI_PSPS = {
    "okaxis", "okicici", "oksbi", "okhdfcbank", "paytm", "ybl", "upi",
    "icici", "sbi", "axl", "apl", "barodampay", "mahb", "idfcbank",
    "kotak", "indus", "fdb", "postbank", "airtel", "amazonpay"
}

# Standardized Claimed Agency Names
AGENCY_MAP = {
    "mumbai police": "Mumbai Police Cyber Cell",
    "delhi police": "Delhi Police Cyber Crime Unit",
    "trai": "TRAI Telecom Department",
    "cbi": "CBI Cyber Crime Division",
    "cyber crime cell": "Cyber Crime Cell",
    "enforcement directorate": "Enforcement Directorate (ED)",
    "ed": "Enforcement Directorate (ED)",
    "supreme court": "Supreme Court of India",
    "rbi": "Reserve Bank of India (RBI)",
    "customs department": "Customs Department"
}


class ThreatPostProcessor:
    """
    Regex-based post-processor to clean, validate, normalize, and deduplicate
    extracted threat parameters (UPI IDs, Phone Numbers, Badge IDs, URLs, Case IDs).
    """
    def __init__(self):
        pass

    @staticmethod
    def clean_raw_string(val: str) -> str:
        """Strips quotes, backticks, brackets, and leading/trailing punctuation."""
        if not val:
            return ""
        val = str(val).strip()
        val = re.sub(r"^[^\w@]+|[^\w@]+$", "", val)
        return val.strip()

    @staticmethod
    def validate_upi(raw_upi: str) -> Optional[str]:
        """
        Validates and cleans UPI handles.
        Format: username@psp
        """
        cleaned = ThreatPostProcessor.clean_raw_string(raw_upi).lower()
        
        # Match username@psp regex
        match = re.match(r"^([a-zA-Z0-9._-]+)@([a-zA-Z0-9.-]+)$", cleaned)
        if not match:
            return None

        username, handle = match.group(1), match.group(2)
        handle = handle.rstrip(".")
        if len(username) < 2 or len(handle) < 2:
            return None

        # Check if handle is a known payment handle or valid handle pattern
        if handle in VALID_UPI_PSPS or any(psp in handle for psp in VALID_UPI_PSPS) or len(handle) <= 10:
            return f"{username}@{handle}"

        return None

    @staticmethod
    def validate_phone_number(raw_phone: str) -> Optional[str]:
        """
        Validates 10-digit Indian mobile numbers (starts with 6, 7, 8, 9).
        Formats as +91-XXXXX-XXXXX.
        """
        cleaned = ThreatPostProcessor.clean_raw_string(raw_phone)
        # Strip spaces, dashes, +91, 91, 0 prefixes
        digits = re.sub(r"\D", "", cleaned)

        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]

        if len(digits) == 10 and digits[0] in "6789":
            return f"+91-{digits[:5]}-{digits[5:]}"

        return None

    @staticmethod
    def validate_url(text: str) -> List[str]:
        """Extracts and validates HTTP/HTTPS URLs and phishing domain endpoints."""
        url_pattern = r"\b(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(?:/[^\s]*)?\b"
        valid_urls = []

        for match in re.finditer(url_pattern, text):
            start = match.start()
            if start > 0 and text[start - 1] == "@":
                continue

            url = match.group(0).lower()
            url = ThreatPostProcessor.clean_raw_string(url)

            if "@" in url:
                continue

            if not url.startswith("http://") and not url.startswith("https://"):
                url = f"http://{url}"

            if len(url) > 8 and "." in url:
                valid_urls.append(url)

        return valid_urls

    @staticmethod
    def clean_identifier(raw_id: str) -> Optional[str]:
        """Cleans badge IDs and case/warrant reference numbers."""
        cleaned = ThreatPostProcessor.clean_raw_string(raw_id)
        cleaned = re.sub(r"^(?:badge|officer|case|ref|file|warrant|notice|id)\s*#?\s*", "", cleaned, flags=re.IGNORECASE).strip()
        cleaned = re.sub(r"^#\s*", "", cleaned).strip()
        
        if len(cleaned) >= 3 and any(c.isalnum() for c in cleaned):
            return cleaned.upper()
        return None

    @staticmethod
    def clean_agency(raw_agency: str) -> Optional[str]:
        """Normalizes claimed agency names into standardized official titles."""
        cleaned = ThreatPostProcessor.clean_raw_string(raw_agency).lower()
        
        for key, official_name in AGENCY_MAP.items():
            if key in cleaned:
                return official_name

        if len(cleaned) >= 3:
            return raw_agency.strip().title()

        return None

    def extract_and_validate_all(
        self,
        transcript_text: str = "",
        raw_entities: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Alias for process_extracted_threats."""
        return self.process_extracted_threats(raw_entities=raw_entities or [], transcript_text=transcript_text)

    def process_extracted_threats(
        self,
        raw_entities: List[Dict[str, Any]],
        transcript_text: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validates, cleans, deduplicates, and formats extracted threat entities.
        Returns a structured threat intelligence report dictionary.
        """
        upi_set: Set[str] = set()
        phone_set: Set[str] = set()
        badge_set: Set[str] = set()
        case_set: Set[str] = set()
        agency_set: Set[str] = set()
        url_set: Set[str] = set()

        # Extract URLs from transcript text if provided
        if transcript_text:
            for url in self.validate_url(transcript_text):
                url_set.add(url)

        # Process raw entities
        for ent in raw_entities:
            text_val = ent.get("text", "")
            label_val = str(ent.get("label", "")).lower()

            if "upi" in label_val:
                valid_upi = self.validate_upi(text_val)
                if valid_upi:
                    upi_set.add(valid_upi)
            elif "phone" in label_val or "mobile" in label_val:
                valid_phone = self.validate_phone_number(text_val)
                if valid_phone:
                    phone_set.add(valid_phone)
            elif "badge" in label_val:
                valid_badge = self.clean_identifier(text_val)
                if valid_badge:
                    badge_set.add(valid_badge)
            elif "case" in label_val or "court" in label_val or "warrant" in label_val:
                valid_case = self.clean_identifier(text_val)
                if valid_case:
                    case_set.add(valid_case)
            elif "agency" in label_val or "department" in label_val:
                valid_agency = self.clean_agency(text_val)
                if valid_agency:
                    agency_set.add(valid_agency)
            elif "url" in label_val or "website" in label_val:
                for url in self.validate_url(text_val):
                    url_set.add(url)

        total_valid = len(upi_set) + len(phone_set) + len(badge_set) + len(case_set) + len(agency_set) + len(url_set)

        return {
            "upi_ids": sorted(list(upi_set)),
            "phone_numbers": sorted(list(phone_set)),
            "urls": sorted(list(url_set)),
            "police_badge_ids": sorted(list(badge_set)),
            "case_ids": sorted(list(case_set)),
            "claimed_agencies": sorted(list(agency_set)),
            "total_valid_threat_indicators": total_valid
        }
