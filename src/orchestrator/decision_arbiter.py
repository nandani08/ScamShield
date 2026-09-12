"""
Decision Arbiter Subsystem (Unified Dual-Engine Orchestrator).

Integrates:
- Engine 1 (ProtocolVerifier): Purely deterministic compliance rule engine for rogue insider detection.
- Engine 2 (TriStateDetector): Fine-tuned Multitask MuRIL classifier for external scam detection.
- Shared Honeypot (HoneypotPersonaAdapter): Qwen2.5-7B state machine supporting dual persona modes:
  * Mode A: Digital Arrest Victim
  * Mode B: Confused Bank Customer
- Threat Extractor (GLiNERThreatExtractor & ThreatPostProcessor): Structured threat logging.
"""

import logging
from typing import Dict, Any, List, Optional

from src.rules.protocol_verifier import ProtocolVerifier
from src.detection.tristate_detector import TriStateDetector
from src.honeypot.persona_adapter import HoneypotPersonaAdapter, PersonaMode
from src.extraction.gliner_extractor import GLiNERThreatExtractor
from src.extraction.post_processor import ThreatPostProcessor
from src.config import settings

logger = logging.getLogger("ArrestShield.DecisionArbiter")


class DecisionArbiter:
    """
    Unified Decision Arbiter coordinating Dual-Engine detection and Honeypot routing.
    """
    def __init__(
        self,
        verifier: Optional[ProtocolVerifier] = None,
        detector: Optional[TriStateDetector] = None,
        persona_adapter: Optional[HoneypotPersonaAdapter] = None,
        threat_extractor: Optional[GLiNERThreatExtractor] = None,
        post_processor: Optional[ThreatPostProcessor] = None
    ):
        self.verifier = verifier if verifier is not None else ProtocolVerifier()
        self.detector = detector if detector is not None else TriStateDetector()
        self.persona_adapter = persona_adapter if persona_adapter is not None else HoneypotPersonaAdapter()
        self.threat_extractor = threat_extractor if threat_extractor is not None else GLiNERThreatExtractor(model_name="dummy")
        self.post_processor = post_processor if post_processor is not None else ThreatPostProcessor()

        self.cumulative_threats: Dict[str, Any] = {
            "upi_ids": [],
            "phone_numbers": [],
            "urls": [],
            "police_badge_ids": [],
            "case_ids": [],
            "claimed_agencies": [],
            "total_valid_threat_indicators": 0
        }

    def reset(self):
        """Resets session state across all engines and threat stores."""
        self.detector.reset()
        self.persona_adapter.reset()
        self.cumulative_threats = {
            "upi_ids": [],
            "phone_numbers": [],
            "urls": [],
            "police_badge_ids": [],
            "case_ids": [],
            "claimed_agencies": [],
            "total_valid_threat_indicators": 0
        }
        logger.info("DecisionArbiter session reset successfully.")

    def process_transcript_turn(self, text: str, timestamp_ms: int = 0) -> Dict[str, Any]:
        """
        Processes a transcript turn through both engines, evaluates honeypot trigger,
        determines persona mode, generates response, and extracts threat intelligence.
        """
        if not text or not text.strip():
            return {
                "type": "decision_arbiter_turn",
                "transcript": "",
                "timestamp_ms": timestamp_ms,
                "engine1_insider_verifier": self.verifier.verify_transcript(""),
                "engine2_external_detector": {"state": "SAFE", "risk_score": 0.0},
                "trigger_honeypot": False,
                "honeypot": {"active": False},
                "threat_extraction": self.post_processor.extract_and_validate_all(""),
                "cumulative_threats": self.cumulative_threats
            }

        # 1. Evaluate Engine 1 (Protocol Verifier - Rogue Insider)
        verifier_result = self.verifier.verify_transcript(text)

        # 2. Evaluate Engine 2 (MuRIL Risk Engine - External Scams)
        detection_result = self.detector.process_turn(text)

        # 3. Decision Arbitration Logic
        is_insider_violation = verifier_result["is_insider_violation"]
        is_external_fraud = (
            detection_result["state"] == "FRAUD" or 
            detection_result["risk_score"] >= settings.detection.fraud_threshold or
            detection_result["state"] == "UNCERTAIN" or
            detection_result["risk_score"] >= 0.40
        )

        trigger_honeypot = is_insider_violation or is_external_fraud

        # 4. Route Persona Mode
        if is_insider_violation:
            target_persona_mode = PersonaMode.CONFUSED_BANK_CUSTOMER
        elif is_external_fraud:
            target_persona_mode = PersonaMode.DIGITAL_ARREST_VICTIM
        else:
            target_persona_mode = self.persona_adapter.mode

        # 5. Honeypot Execution
        honeypot_payload = {"active": False}
        if trigger_honeypot:
            honeypot_turn = self.persona_adapter.generate_turn(
                scammer_input=text,
                detection_result=detection_result,
                insider_violation_result=verifier_result,
                forced_mode=target_persona_mode
            )
            honeypot_payload = {
                "active": True,
                "mode": honeypot_turn["mode"],
                "state": honeypot_turn["state"],
                "victim_response": honeypot_turn["victim_response"],
                "turn_count": honeypot_turn["turn_count"],
                "utility_score": honeypot_turn["utility_score"]
            }

        # 6. Zero-Shot Threat Intelligence Extraction (GLiNER + Post-Processor)
        raw_gliner_entities = self.threat_extractor.predict_entities(text)
        threat_report = self.post_processor.extract_and_validate_all(text, raw_gliner_entities)

        # Accumulate threat indicators
        for key in ["upi_ids", "phone_numbers", "urls", "police_badge_ids", "case_ids", "claimed_agencies"]:
            existing_set = set(self.cumulative_threats[key])
            existing_set.update(threat_report[key])
            self.cumulative_threats[key] = sorted(list(existing_set))

        self.cumulative_threats["total_valid_threat_indicators"] = sum(
            len(self.cumulative_threats[k]) for k in ["upi_ids", "phone_numbers", "urls", "police_badge_ids", "case_ids", "claimed_agencies"]
        )

        return {
            "type": "decision_arbiter_turn",
            "transcript": text,
            "timestamp_ms": timestamp_ms,
            "engine1_insider_verifier": verifier_result,
            "engine2_external_detector": detection_result,
            "trigger_honeypot": trigger_honeypot,
            "honeypot": honeypot_payload,
            "threat_extraction": threat_report,
            "cumulative_threats": self.cumulative_threats
        }
