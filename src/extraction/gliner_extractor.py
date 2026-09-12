import re
import logging
from typing import List, Dict, Any, Optional

from src.config import settings

logger = logging.getLogger("ArrestShield.GLiNERExtractor")


class DummyThreatExtractor:
    """
    Rule-based Fallback Threat Extractor for test/offline environments.
    Scans transcripts for UPI IDs, Phone Numbers, Badge IDs, Case IDs, and Claimed Agencies.
    """
    def __init__(self, labels: Optional[List[str]] = None):
        self.labels = labels if labels else settings.extraction.entity_labels

    def predict_entities(self, text: str, labels: Optional[List[str]] = None, threshold: float = 0.5) -> List[Dict[str, Any]]:
        entities = []
        if not text or not text.strip():
            return entities

        # 1. UPI ID Regex
        upi_pattern = r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\b"
        for match in re.finditer(upi_pattern, text):
            entities.append({
                "text": match.group(0),
                "label": "UPI ID",
                "score": 0.95,
                "start": match.start(),
                "end": match.end()
            })

        # 2. Phone Number Regex (10-digit starting with 6-9)
        phone_pattern = r"\b[6-9]\d{9}\b"
        for match in re.finditer(phone_pattern, text):
            entities.append({
                "text": match.group(0),
                "label": "phone number",
                "score": 0.92,
                "start": match.start(),
                "end": match.end()
            })

        # 3. Police Badge ID (e.g. Badge #MH-9812, ID: 4921)
        badge_pattern = r"\b(?:badge|officer id|badge id|id)\s*#?\s*([a-zA-Z0-9-]+)\b"
        for match in re.finditer(badge_pattern, text, flags=re.IGNORECASE):
            entities.append({
                "text": match.group(1),
                "label": "police badge ID",
                "score": 0.88,
                "start": match.start(1),
                "end": match.end(1)
            })

        # 4. Case ID / Court Reference Number (e.g. CR-2024-9812, Case #9821, Ref #4912)
        case_pattern = r"\b(?:warrant case|case|ref|file|warrant|notice)\s*#?\s*([a-zA-Z0-9/-]{3,})\b"
        for match in re.finditer(case_pattern, text, flags=re.IGNORECASE):
            val = match.group(1)
            if any(c.isdigit() for c in val):
                entities.append({
                    "text": val,
                    "label": "case ID",
                    "score": 0.89,
                    "start": match.start(1),
                    "end": match.end(1)
                })

        # 5. Claimed Agencies (e.g. Mumbai Police, TRAI, CBI, Cyber Crime Cell, Enforcement Directorate, Supreme Court)
        agency_pattern = r"\b(Mumbai Police|Delhi Police|TRAI|CBI|Cyber Crime Cell|Enforcement Directorate|ED|Supreme Court|RBI|Customs Department)\b"
        for match in re.finditer(agency_pattern, text, flags=re.IGNORECASE):
            entities.append({
                "text": match.group(0),
                "label": "claimed agency",
                "score": 0.94,
                "start": match.start(),
                "end": match.end()
            })

        return entities


class GLiNERThreatExtractor:
    """
    Zero-Shot Real-Time Threat Extraction Engine using GLiNER.
    
    Parses conversational transcripts for custom threat parameters:
    - UPI IDs
    - Phone numbers
    - Police badge IDs
    - Court reference numbers
    - Claimed agencies
    - Case IDs
    """
    def __init__(
        self,
        model_name: Optional[str] = None,
        labels: Optional[List[str]] = None,
        threshold: float = 0.5
    ):
        self.model_name = model_name if model_name is not None else settings.extraction.gliner_model
        self.labels = labels if labels is not None else settings.extraction.entity_labels
        self.threshold = threshold

        self.model = None
        if self.model_name != "dummy":
            try:
                from gliner import GLiNER
                self.model = GLiNER.from_pretrained(self.model_name, local_files_only=True)
                logger.info(f"Loaded GLiNER model '{self.model_name}' locally.")
            except Exception:
                try:
                    from gliner import GLiNER
                    self.model = GLiNER.from_pretrained(self.model_name)
                    logger.info(f"Loaded GLiNER model '{self.model_name}' online.")
                except Exception as e:
                    logger.warning(f"Could not load GLiNER model '{self.model_name}' ({e}). Falling back to rule-based ThreatExtractor.")
                    self.model = DummyThreatExtractor(labels=self.labels)
        else:
            self.model = DummyThreatExtractor(labels=self.labels)

    def predict_entities(self, text: str, labels: Optional[List[str]] = None, threshold: Optional[float] = None) -> List[Dict[str, Any]]:
        """Alias for extract_threat_entities."""
        return self.extract_threat_entities(text, threshold=threshold)

    def extract_threat_entities(self, text: str, threshold: Optional[float] = None) -> List[Dict[str, Any]]:
        """
        Extracts zero-shot threat entities from transcript text.
        Returns list of dicts with 'text', 'label', 'score', 'start', 'end'.
        """
        if not text or not text.strip():
            return []

        th = threshold if threshold is not None else self.threshold

        try:
            if hasattr(self.model, "predict_entities"):
                results = self.model.predict_entities(text, self.labels, threshold=th)
            else:
                fallback = DummyThreatExtractor(labels=self.labels)
                results = fallback.predict_entities(text, self.labels, threshold=th)
        except Exception as e:
            logger.warning(f"GLiNER prediction failed ({e}). Falling back to rule-based extraction.")
            fallback = DummyThreatExtractor(labels=self.labels)
            results = fallback.predict_entities(text, self.labels, threshold=th)

        formatted_results = []
        for r in results:
            formatted_results.append({
                "text": str(r.get("text", "")).strip(),
                "label": str(r.get("label", "")).strip(),
                "score": float(round(r.get("score", 0.0), 4)),
                "start": int(r.get("start", 0)),
                "end": int(r.get("end", 0))
            })

        return formatted_results
