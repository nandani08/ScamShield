"""
Protocol Verifier Subsystem (Engine 1 - Rogue Insider Detector).

Purely deterministic compliance rule engine enforcing banking invariants based on RBI guidelines.
Evaluates Separation of Duties and State Inversion checks on incoming transcript text.
"""

import re
from typing import Dict, Any, List, Optional
from src.rules.banking_invariants import (
    EXECUTIVE_ROLES,
    PROHIBITED_DEMANDS,
    URGENCY_TRIGGERS,
    LIVE_CALL_VERIFICATION_KEYWORDS
)


class ProtocolVerifier:
    """
    Deterministic banking compliance protocol verifier.
    """
    def __init__(self):
        # Sort roles and demands by length descending so longer terms match before shorter subsets
        self.executive_roles = sorted(list(EXECUTIVE_ROLES), key=len, reverse=True)
        self.prohibited_demands = sorted(list(PROHIBITED_DEMANDS), key=len, reverse=True)
        self.urgency_triggers = sorted(list(URGENCY_TRIGGERS), key=len, reverse=True)
        self.live_call_keywords = sorted(list(LIVE_CALL_VERIFICATION_KEYWORDS), key=len, reverse=True)

    def verify_transcript(self, text: str) -> Dict[str, Any]:
        """
        Parses incoming transcript text for protocol violations.
        
        Returns:
            {
                "is_insider_violation": bool,
                "severity": "CRITICAL" | "NONE",
                "violated_rules": List[str],
                "trigger_honeypot": bool,
                "detected_role": Optional[str],
                "detected_demands": List[str]
            }
        """
        if not text or not text.strip():
            return {
                "is_insider_violation": False,
                "severity": "NONE",
                "violated_rules": [],
                "trigger_honeypot": False,
                "detected_role": None,
                "detected_demands": []
            }

        text_lower = text.lower()
        violated_rules: List[str] = []

        # Find claimed executive role
        detected_role: Optional[str] = None
        for role in self.executive_roles:
            if role in text_lower:
                detected_role = role
                break

        # Find prohibited demands
        detected_demands: List[str] = []
        for demand in self.prohibited_demands:
            # Word boundary regex for short acronyms like 'otp', 'pin', 'cvv'
            pattern = rf"\b{re.escape(demand)}\b" if len(demand) <= 5 else re.escape(demand)
            if re.search(pattern, text_lower):
                detected_demands.append(demand)

        # Check 1: Separation of Duties Violation
        # An executive role requesting any prohibited demand (OTP, MPIN, CVV, AnyDesk, escrow transfer, etc.)
        if detected_role and detected_demands:
            for demand in detected_demands:
                rule_desc = f"Separation of Duties Violation: Executive role '{detected_role.title()}' requested prohibited asset '{demand.upper()}'"
                violated_rules.append(rule_desc)
        elif detected_demands and any(k in text_lower for k in ["bank", "branch", "account", "manager", "officer"]):
            # Also catch prohibited demands when bank authority context is present
            for demand in detected_demands:
                rule_desc = f"Separation of Duties Violation: Bank official requested prohibited asset '{demand.upper()}'"
                violated_rules.append(rule_desc)

        # Check 2: State Inversion Violation
        # Caller insists on completing fund movement or verification directly on live voice call
        # rather than directing customer to the official mobile app or physical branch.
        is_live_call_demand = any(kw in text_lower for kw in self.live_call_keywords)
        is_branch_advisory = any(k in text_lower for k in ["visit local branch", "visit nearest branch", "come to branch", "visit branch", "use official app", "open official app"])

        if is_live_call_demand and not is_branch_advisory:
            if detected_demands or detected_role or "transfer" in text_lower or "verify" in text_lower:
                rule_desc = "State Inversion Violation: Insisting on live voice call transaction/verification instead of directing to official app or local branch"
                violated_rules.append(rule_desc)

        is_violation = len(violated_rules) > 0
        severity = "CRITICAL" if is_violation else "NONE"

        return {
            "is_insider_violation": is_violation,
            "severity": severity,
            "violated_rules": list(set(violated_rules)),
            "trigger_honeypot": is_violation,
            "detected_role": detected_role,
            "detected_demands": detected_demands
        }
