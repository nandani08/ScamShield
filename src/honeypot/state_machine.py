import logging
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple

from src.config import settings
from src.honeypot.llm_client import HoneypotLLMClient

logger = logging.getLogger("ArrestShield.HoneypotStateMachine")


class HoneypotState(str, Enum):
    CONFUSED = "confused"
    FRIGHTENED = "frightened"
    COOPERATIVE = "cooperative"
    STALLING = "stalling"


class HoneypotStateMachine:
    """
    Adaptive State Machine for the LLM Honeypot Engine.
    
    Tracks dialogue turns and dynamically transitions through psychological states:
    CONFUSED -> FRIGHTENED -> COOPERATIVE -> STALLING
    
    Calculates Utility Optimization Score:
    Utility = alpha * (Extracted Threat Indicators) - beta * (PII Leak Risk)
    """
    def __init__(
        self,
        llm_client: Optional[HoneypotLLMClient] = None,
        alpha_utility: Optional[float] = None,
        beta_utility: Optional[float] = None
    ):
        self.llm_client = llm_client if llm_client is not None else HoneypotLLMClient()
        self.alpha_utility = alpha_utility if alpha_utility is not None else settings.honeypot.alpha_utility
        self.beta_utility = beta_utility if beta_utility is not None else settings.honeypot.beta_utility

        self.current_state: HoneypotState = HoneypotState.CONFUSED
        self.turn_count: int = 0
        self.history: List[Dict[str, str]] = []
        self.extracted_indicators_count: int = 0
        self.pii_risk_score: float = 0.0

    def reset(self):
        """Resets the state machine and conversation history."""
        self.current_state = HoneypotState.CONFUSED
        self.turn_count = 0
        self.history.clear()
        self.extracted_indicators_count = 0
        self.pii_risk_score = 0.0

    def determine_next_state(
        self,
        scammer_input: str,
        detection_result: Optional[Dict[str, Any]] = None
    ) -> HoneypotState:
        """
        Determines state machine transition based on dialogue input, detection stage, and turn count.
        """
        scammer_lower = scammer_input.lower()
        predicted_stage = detection_result.get("predicted_stage", "").lower() if detection_result else ""
        triggers = detection_result.get("triggers", {}) if detection_result else {}

        payment_pressure = triggers.get("payment_pressure", 0.0)
        authority_score = triggers.get("authority", 0.0)
        urgency_score = triggers.get("urgency", 0.0)

        # Transition Rules
        if payment_pressure > 0.6 or predicted_stage == "payment" or any(kw in scammer_lower for kw in ["transfer", "upi", "pay", "send money", "gpay", "phonepe", "bank account", "otp"]):
            next_state = HoneypotState.STALLING
        elif predicted_stage in ["coercion", "isolation"] or self.turn_count >= 3:
            next_state = HoneypotState.COOPERATIVE
        elif authority_score > 0.5 or urgency_score > 0.5 or predicted_stage in ["allegation", "impersonation"] or self.turn_count >= 1:
            next_state = HoneypotState.FRIGHTENED
        else:
            next_state = HoneypotState.CONFUSED

        # Maintain progression order (do not regress to confused once frightened)
        state_order = [HoneypotState.CONFUSED, HoneypotState.FRIGHTENED, HoneypotState.COOPERATIVE, HoneypotState.STALLING]
        current_idx = state_order.index(self.current_state)
        next_idx = state_order.index(next_state)

        if next_idx > current_idx:
            return next_state
        return self.current_state

    def calculate_utility_score(self, new_extracted_count: int = 0, pii_leak_penalty: float = 0.0) -> float:
        """
        Calculates Utility Function:
        Utility = alpha * (Total Extracted Indicators) - beta * (PII Risk Score)
        """
        self.extracted_indicators_count += new_extracted_count
        self.pii_risk_score += pii_leak_penalty

        utility = (self.alpha_utility * self.extracted_indicators_count) - (self.beta_utility * self.pii_risk_score)
        return float(round(utility, 4))

    def generate_honeypot_turn(
        self,
        scammer_input: str,
        detection_result: Optional[Dict[str, Any]] = None,
        decoy_context: Optional[str] = None,
        new_extracted_count: int = 0,
        mode: str = "digital_arrest_victim"
    ) -> Dict[str, Any]:
        """
        Processes incoming scammer turn, updates state machine, and generates synthetic victim response.
        """
        self.turn_count += 1
        previous_state = self.current_state

        # Determine state transition
        self.current_state = self.determine_next_state(scammer_input, detection_result)
        state_changed = (self.current_state != previous_state)

        # Append scammer turn to history
        self.history.append({"role": "user", "content": scammer_input.strip()})

        # Generate response via LLM Client
        victim_response = self.llm_client.generate_response(
            conversation_history=self.history,
            stage=self.current_state.value,
            decoy_context=decoy_context,
            mode=mode
        )

        # Append assistant victim response to history
        self.history.append({"role": "assistant", "content": victim_response})

        # Calculate utility score
        utility_score = self.calculate_utility_score(new_extracted_count=new_extracted_count)

        logger.info(f"Honeypot Turn {self.turn_count} [{previous_state.value} -> {self.current_state.value}] | Utility: {utility_score}")

        return {
            "state": self.current_state.value,
            "previous_state": previous_state.value,
            "state_changed": state_changed,
            "victim_response": victim_response,
            "turn_count": self.turn_count,
            "utility_score": utility_score,
            "extracted_indicators_count": self.extracted_indicators_count
        }
