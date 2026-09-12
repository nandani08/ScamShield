"""
Banking Invariants & Regulatory Compliance Taxonomies (Engine 1 - Rogue Insider Detection).

Defines deterministic compliance rules based on RBI guidelines and standard banking security protocols.
"""

from typing import Set, Dict, List

# Executive roles within banking institutions that must adhere to separation of duties
EXECUTIVE_ROLES: Set[str] = {
    "branch manager",
    "bank manager",
    "manager",
    "chief manager",
    "vigilance officer",
    "nodal officer",
    "cyber cell incharge",
    "bank officer",
    "officer",
    "branch head",
    "accounts manager",
    "general manager",
    "relationship manager",
    "branch executive"
}

# Strict security prohibitions - Bank staff are strictly forbidden from asking for these
PROHIBITED_DEMANDS: Set[str] = {
    "otp",
    "one time password",
    "mpin",
    "pin",
    "cvv",
    "anydesk",
    "teamviewer",
    "quicksupport",
    "remote access",
    "external upi",
    "escrow account",
    "escrow transfer",
    "security deposit",
    "personal transfer",
    "screen share",
    "screen sharing"
}

# Artificial urgency patterns used in compliance coercion
URGENCY_TRIGGERS: Set[str] = {
    "account suspension",
    "account block",
    "immediate arrest",
    "zero cooling period",
    "10 minutes deadline",
    "immediate transfer",
    "account freeze",
    "police report"
}

# Live call fund movement keywords (State Inversion check)
LIVE_CALL_VERIFICATION_KEYWORDS: Set[str] = {
    "over the phone",
    "on this call",
    "right now on call",
    "live call transfer",
    "tell me the code now",
    "share screen right now",
    "verify on call"
}
