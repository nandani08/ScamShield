import re
import random
import logging
from typing import Dict, Any, List, Tuple, Optional

logger = logging.getLogger("ArrestShield.SyntheticEntityVault")

# Pre-validated realistic synthetic decoy datasets
DECOY_BANK_ACCOUNTS = [
    {
        "bank_name": "State Bank of India",
        "account_number": "39810475821",
        "ifsc_code": "SBIN0004321",
        "account_holder": "Ramesh Chandra Gupta",
        "branch": "Civil Lines, Nagpur"
    },
    {
        "bank_name": "HDFC Bank",
        "account_number": "50100298471203",
        "ifsc_code": "HDFC0001234",
        "account_holder": "Ramesh Chandra Gupta",
        "branch": "Dharampeth, Nagpur"
    },
    {
        "bank_name": "ICICI Bank",
        "account_number": "002401589342",
        "ifsc_code": "ICIC0000024",
        "account_holder": "Ramesh Chandra Gupta",
        "branch": "Wardha Road, Nagpur"
    }
]

DECOY_UPI_IDS = [
    "ramesh.gupta52@okaxis",
    "guptastores.ngp@upi",
    "ramesh.shop@paytm",
    "rg.nagpur@ybl",
    "ramesh.gupta@icici"
]

DECOY_NAMES = [
    "Ramesh Chandra Gupta",
    "Suresh Kumar Verma",
    "Rajesh Sharma",
    "Mahesh Prasad"
]

DECOY_ID_CARDS = {
    "aadhar": "9876 5432 1098",
    "pan": "ABCDP1234F",
    "voter_id": "NGP1234567"
}

DECOY_ADDRESS = "Plot No. 45, Civil Lines, Near Variety Square, Nagpur, Maharashtra - 440001"


class SyntheticEntityVault:
    """
    Synthetic Entity Vault.
    
    Dynamically manages, generates, and intercepts sensitive credentials/PII,
    replacing real coordinates with pre-validated decoy synthetic data.
    """
    def __init__(self):
        self.active_bank_account = random.choice(DECOY_BANK_ACCOUNTS)
        self.active_upi = random.choice(DECOY_UPI_IDS)
        self.active_name = random.choice(DECOY_NAMES)
        self.active_address = DECOY_ADDRESS
        self.intercept_log: List[Dict[str, str]] = []

    def reset_active_decoys(self):
        """Resets active synthetic decoys to fresh randomized credentials."""
        self.active_bank_account = random.choice(DECOY_BANK_ACCOUNTS)
        self.active_upi = random.choice(DECOY_UPI_IDS)
        self.active_name = random.choice(DECOY_NAMES)
        self.active_address = DECOY_ADDRESS
        self.intercept_log.clear()
        logger.info(f"Reset active synthetic vault decoys: {self.active_name} | {self.active_bank_account['bank_name']} | {self.active_upi}")

    def reset(self):
        """Alias for reset_active_decoys."""
        self.reset_active_decoys()

    def get_decoy_credentials(self) -> Dict[str, Any]:
        """
        Returns a structured dictionary of synthetic decoy credentials
        to inject into LLM Honeypot prompts or system context.
        """
        return {
            "name": self.active_name,
            "bank_name": self.active_bank_account["bank_name"],
            "account_number": self.active_bank_account["account_number"],
            "ifsc_code": self.active_bank_account["ifsc_code"],
            "upi_id": self.active_upi,
            "aadhar_number": DECOY_ID_CARDS["aadhar"],
            "pan_number": DECOY_ID_CARDS["pan"],
            "address": self.active_address,
            "decoy_otp": self.generate_decoy_otp(6)
        }

    def get_decoy_context_string(self) -> str:
        """
        Formats synthetic decoy credentials into a clean text block for LLM prompts.
        """
        creds = self.get_decoy_credentials()
        return (
            f"- Name: {creds['name']}\n"
            f"- Bank: {creds['bank_name']} (A/C: {creds['account_number']}, IFSC: {creds['ifsc_code']})\n"
            f"- UPI ID: {creds['upi_id']}\n"
            f"- Aadhar Number: {creds['aadhar_number']}\n"
            f"- PAN Card: {creds['pan_number']}\n"
            f"- Address: {creds['address']}\n"
            f"- Decoy OTP: {creds['decoy_otp']}"
        )

    def generate_decoy_otp(self, length: int = 6) -> str:
        """Generates a realistic 4-digit or 6-digit synthetic decoy OTP."""
        if length == 4:
            return f"{random.randint(1000, 9999)}"
        return f"{random.randint(100000, 999999)}"

    def sanitize_and_intercept(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Intercepts PII or payment patterns in text and swaps them out with synthetic decoy placeholders.
        Returns (sanitized_text, replacements_dict).
        """
        replacements: Dict[str, str] = {}
        sanitized = text

        # 1. Intercept 12-digit Aadhar format (e.g. 1234 5678 9012 or 123456789012)
        aadhar_pattern = r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
        for match in re.findall(aadhar_pattern, sanitized):
            decoy_val = DECOY_ID_CARDS["aadhar"]
            sanitized = sanitized.replace(match, decoy_val)
            replacements[match] = decoy_val

        # 2. Intercept 10-digit Indian Mobile Numbers starting with 6-9
        phone_pattern = r"\b[6-9]\d{9}\b"
        for match in re.findall(phone_pattern, sanitized):
            decoy_val = "9876543210"
            sanitized = sanitized.replace(match, decoy_val)
            replacements[match] = decoy_val

        # 3. Intercept UPI IDs (e.g. word@bank format)
        upi_pattern = r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\b"
        for match in re.findall(upi_pattern, sanitized):
            decoy_val = self.active_upi
            sanitized = sanitized.replace(match, decoy_val)
            replacements[match] = decoy_val

        # 4. Intercept 6-digit OTP codes
        otp_pattern = r"\b(OTP|code|pin)\s*(?:is|:|=)?\s*(\d{6})\b"
        for match in re.finditer(otp_pattern, sanitized, flags=re.IGNORECASE):
            raw_otp = match.group(2)
            decoy_otp = self.generate_decoy_otp(6)
            sanitized = sanitized.replace(raw_otp, decoy_otp)
            replacements[raw_otp] = decoy_otp

        if replacements:
            logger.info(f"Intercepted {len(replacements)} sensitive PII items and swapped with synthetic vault decoys.")
            self.intercept_log.append(replacements)

        return sanitized, replacements
