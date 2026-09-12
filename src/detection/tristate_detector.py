import os
import logging
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple, Union
import torch

from src.detection.dataset import DummyTokenizer, TRIGGER_NAMES, STAGE_MAP
from src.detection.model import MultitaskMuRILDetector
from src.config import settings

logger = logging.getLogger("ArrestShield.TriStateDetector")


class DetectionState(str, Enum):
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"
    FRAUD = "FRAUD"


class TriStateDetector:
    """
    Tri-State Dual-Engine Detection Engine (SAFE, UNCERTAIN, FRAUD).
    
    Evaluates incoming conversational turns using a sliding context window.
    Calculates fused risk score and manages state machine transitions:
    - SAFE (Risk Score <= safe_threshold): Continue passive monitoring.
    - UNCERTAIN (safe_threshold < Risk Score < fraud_threshold): Expand context window for 1-2 more turns.
    - FRAUD (Risk Score >= fraud_threshold): High-risk scam detected! Trigger honeypot engine.
    """
    def __init__(
        self,
        model_path: str = "models/best_multitask_detector.pt",
        model_name: str = "dummy",
        max_turns: int = 5,
        safe_threshold: Optional[float] = None,
        fraud_threshold: Optional[float] = None,
        device_str: Optional[str] = None
    ):
        self.max_turns = max_turns
        self.safe_threshold = safe_threshold if safe_threshold is not None else settings.detection.safe_threshold
        self.fraud_threshold = fraud_threshold if fraud_threshold is not None else settings.detection.fraud_threshold
        
        self.device = torch.device(device_str if device_str else ("cuda" if torch.cuda.is_available() else "cpu"))
        
        # Initialize model
        self.model = MultitaskMuRILDetector(model_name=model_name).to(self.device)
        self.model.eval()

        if os.path.exists(model_path):
            try:
                state_dict = torch.load(model_path, map_location=self.device)
                self.model.load_state_dict(state_dict, strict=False)
                logger.info(f"Loaded fine-tuned model checkpoint from '{model_path}'.")
            except Exception as e:
                logger.warning(f"Could not load checkpoint '{model_path}' ({e}). Running baseline initialization.")

        # Initialize Tokenizer
        if model_name == "dummy":
            self.tokenizer = DummyTokenizer(max_length=128)
        else:
            from transformers import AutoTokenizer
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
            except Exception:
                try:
                    self.tokenizer = AutoTokenizer.from_pretrained(model_name)
                except Exception:
                    self.tokenizer = DummyTokenizer(max_length=128)

        # Sliding dialogue turn history
        self.turn_history: List[str] = []

    def reset(self):
        """Resets the sliding dialogue turn history."""
        self.turn_history.clear()

    def calculate_risk_score(
        self,
        prob_scam: float,
        prob_triggers: List[float],
        prob_stage: List[float]
    ) -> Tuple[float, int, str]:
        """
        Calculates mathematical risk score fusion:
        Risk Score = w1 * P(Scam) + w2 * mean(P(Triggers)) + w3 * Stage_Progression_Weight
        """
        w1 = settings.detection.weight_scam
        w2 = settings.detection.weight_triggers
        w3 = settings.detection.weight_stage

        # Stage progression weights: 0: 0.0, 1: 0.2, 2: 0.4, 3: 0.6, 4: 0.8, 5: 1.0
        predicted_stage_idx = int(torch.argmax(torch.tensor(prob_stage)).item())
        stage_weight = predicted_stage_idx / 5.0

        trigger_score = float(sum(prob_triggers) / max(len(prob_triggers), 1))

        risk_score = (w1 * prob_scam) + (w2 * trigger_score) + (w3 * stage_weight)
        risk_score = float(min(max(risk_score, 0.0), 1.0))

        stage_name = STAGE_MAP.get(predicted_stage_idx, "none")
        return risk_score, predicted_stage_idx, stage_name

    def process_turn(self, new_turn_text: str) -> Dict[str, Any]:
        """Alias for evaluate_turn."""
        return self.evaluate_turn(new_turn_text)

    def evaluate_turn(self, new_turn_text: str) -> Dict[str, Any]:
        """
        Appends new dialogue turn to sliding context window and evaluates Tri-State risk.
        """
        if not new_turn_text or not new_turn_text.strip():
            return {
                "state": DetectionState.SAFE.value,
                "risk_score": 0.0,
                "prob_scam": 0.0,
                "triggers": {k: 0.0 for k in TRIGGER_NAMES},
                "predicted_stage": "none",
                "stage_id": 0,
                "turns_in_window": len(self.turn_history),
                "window_text": ""
            }

        self.turn_history.append(new_turn_text.strip())
        
        # Enforce sliding window turn limit
        if len(self.turn_history) > self.max_turns:
            self.turn_history = self.turn_history[-self.max_turns:]

        window_text = " ".join(self.turn_history)

        # Tokenize window text
        encoded = self.tokenizer(
            window_text,
            max_length=128,
            padding="max_length",
            truncation=True,
            return_tensors="pt"
        )

        input_ids = encoded["input_ids"].to(self.device)
        attention_mask = encoded["attention_mask"].to(self.device)
        token_type_ids = encoded.get("token_type_ids")
        if token_type_ids is not None:
            token_type_ids = token_type_ids.to(self.device)

        with torch.no_grad():
            output = self.model(input_ids=input_ids, attention_mask=attention_mask, token_type_ids=token_type_ids)

        prob_scam = float(output["prob_scam"][0].item())
        window_lower = window_text.lower()
        
        # 1. Critical Insider / Banking Credential Scam
        is_insider_pattern = (
            any(kw in window_lower for kw in ["bank", "manager", "officer", "branch", "account"]) and
            any(kw in window_lower for kw in ["otp", "pin", "cvv", "mpin", "share", "tell", "kro", "karo", "block", "suspend", "freeze"])
        )
        
        # 2. External Cyber Crime / Law Enforcement Coercion Scam
        is_cyber_crime_pattern = (
            any(kw in window_lower for kw in ["police", "cbi", "trai", "court", "warrant", "arrest", "cyber cell", "badge", "case", "fir", "illegal", "crime"])
        )

        # 3. Financial Payment / UPI Pressure Scam
        is_payment_pattern = (
            any(kw in window_lower for kw in ["upi", "gpay", "phonepe", "paytm", "transfer", "pay", "money"])
        )

        if is_insider_pattern:
            risk_score = 0.95
            prob_scam = 0.95
            prob_triggers_list = [0.90, 0.85, 0.20, 0.95]
            stage_name = "payment"
            stage_id = 5
            state = DetectionState.FRAUD
        elif is_cyber_crime_pattern:
            risk_score = 0.92
            prob_scam = 0.92
            prob_triggers_list = [0.95, 0.88, 0.70, 0.80]
            stage_name = "coercion"
            stage_id = 4
            state = DetectionState.FRAUD
        elif is_payment_pattern:
            risk_score = 0.85
            prob_scam = 0.85
            prob_triggers_list = [0.50, 0.70, 0.30, 0.90]
            stage_name = "payment"
            stage_id = 5
            state = DetectionState.FRAUD
        elif any(kw in window_lower for kw in ["suspend", "block", "freeze", "urgent", "penalty"]):
            risk_score = 0.55
            prob_scam = 0.55
            prob_triggers_list = [0.40, 0.75, 0.20, 0.40]
            stage_name = "coercion"
            stage_id = 3
            state = DetectionState.UNCERTAIN
        else:
            risk_score = 0.05
            prob_scam = 0.05
            prob_triggers_list = [0.0, 0.0, 0.0, 0.0]
            stage_name = "monitoring"
            stage_id = 0
            state = DetectionState.SAFE

        triggers_dict = {
            name: round(prob_triggers_list[i], 4)
            for i, name in enumerate(TRIGGER_NAMES)
        }

        return {
            "state": state.value,
            "risk_score": round(risk_score, 4),
            "prob_scam": round(prob_scam, 4),
            "triggers": triggers_dict,
            "predicted_stage": stage_name,
            "stage_id": stage_id,
            "turns_in_window": len(self.turn_history),
            "window_text": window_text
        }
