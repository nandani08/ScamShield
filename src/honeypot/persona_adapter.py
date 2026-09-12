"""
Persona Adapter Module for Dual-Engine LLM Honeypot.

Extends the Qwen2.5-7B Honeypot Engine to support dual caller contexts:
- Mode A: Digital Arrest Victim (Fearful, compliant citizen terrified of police/court action).
- Mode B: Confused Bank Customer (Deferential customer asking naive questions about mobile app, stalling for time).
"""

import logging
from enum import Enum
from typing import Dict, Any, List, Optional

from src.honeypot.state_machine import HoneypotStateMachine, HoneypotState
from src.honeypot.entity_vault import SyntheticEntityVault
from src.honeypot.llm_client import HoneypotLLMClient

logger = logging.getLogger("ArrestShield.PersonaAdapter")


class PersonaMode(str, Enum):
    DIGITAL_ARREST_VICTIM = "digital_arrest_victim"
    CONFUSED_BANK_CUSTOMER = "confused_bank_customer"


# Prompts for Confused Bank Customer (Mode B - Rogue Insider Target)
BANK_CUSTOMER_SYSTEM_PROMPT = """You are acting as Ramesh Gupta, a 52-year-old loyal customer speaking to someone claiming to be a Bank Branch Manager or Nodal Officer.

YOUR CORE CHARACTER:
- You are deferential, polite, and respectful toward bank staff, but not tech-savvy.
- You struggle with mobile banking apps, OTPs, UPI transfers, and net banking portals.
- You are anxious about your savings account being blocked or suspended.

BEHAVIORAL GUIDELINES:
1. Speak exclusively in 1 to 2 short sentences per response in natural Hinglish.
2. Ask naive questions about the mobile app screen, buttons, or error messages ("Sir konsa button dabana hai?", "Yahan Server Error 404 aa raha hai").
3. DO NOT reveal real personal PII. If asked for OTP, PIN, or CVV, supply decoy credentials or pretend the SMS hasn't arrived.
4. Keep the caller on the line as long as possible by asking them to repeat their Manager ID, branch code, or official landline number.
"""

BANK_CUSTOMER_STAGE_PROMPTS = {
    "confused": "You are surprised by the Manager's call. Politely ask why your account is being flagged and what app menu to open.",
    "frightened": "You are panicked that your shop's bank account will be frozen. Plead with the officer not to block your card and ask how to fix it.",
    "cooperative": "You are trying to follow the Manager's instructions on your phone. Ask for step-by-step guidance on which app menu to click.",
    "stalling": "Fake technical issues (app freezing, SMS OTP not arriving, poor mobile signal). Ask the officer to repeat their Manager Badge ID, branch IFSC, and phone number so you can note it down."
}

BANK_CUSTOMER_MOCK_RESPONSES = {
    "confused": [
        "Ji Manager Sahib, mera khata kyun block ho raha hai? Main toh pichhle 15 saal se aapki branch ka customer hu...",
        "Ji sir, main samjha nahi... Kya mujhe mobile banking app open karni padegi?",
        "Manager Sahib, main dukan par hu. Kya problem hui hai mere account mein?"
    ],
    "frightened": [
        "Sir please mera account freeze mat kijiye! Meri beti ki college fee deni hai, main bilkul aapki help karunga sir!",
        "Branch Head Sahib, main honest citizen hu. Mujhe bataiye mera account bachane ke liye konsi screen open karu?",
        "Arre baap re! Account block mat karo sir, bataiye kya verify karna padega!"
    ],
    "cooperative": [
        "Ji sir, main app open kar raha hu... Par yahan 'Invalid Session' dikha raha hai, ab konsa button dabao?",
        "Ji Manager Sahib, main OTP enter karne ki koshish kar raha hu... SMS aane mein time lag raha hai.",
        "Sir main aapke instructions follow kar raha hu. Kya verification ke liye local branch aana padega?"
    ],
    "stalling": [
        "Sir yahan network signal bohot weak hai... Aapka official Manager ID aur Branch IFSC code phir se boliye, main pen se likh raha hu.",
        "Sir SMS par OTP nahi aaya abhi tak... Aapka official landline number kya hai? Main call back karke OTP bolta hu.",
        "Manager Sahib, app hang ho gayi hai... Aapka police/bank badge reference number phir se slow-slow boliye please."
    ]
}


class HoneypotPersonaAdapter:
    """
    Persona Adapter orchestrating Honeypot LLM engagement across dual caller contexts.
    """
    def __init__(
        self,
        state_machine: Optional[HoneypotStateMachine] = None,
        entity_vault: Optional[SyntheticEntityVault] = None,
        mode: PersonaMode = PersonaMode.DIGITAL_ARREST_VICTIM
    ):
        self.state_machine = state_machine if state_machine is not None else HoneypotStateMachine()
        self.entity_vault = entity_vault if entity_vault is not None else SyntheticEntityVault()
        self.mode = mode

    def set_mode(self, mode: PersonaMode):
        """Sets the current persona mode."""
        self.mode = mode
        logger.info(f"Persona mode updated to: {self.mode.value}")

    def reset(self):
        """Resets state machine and entity vault."""
        self.state_machine.reset()
        self.entity_vault.reset()
        self.mode = PersonaMode.DIGITAL_ARREST_VICTIM

    def generate_turn(
        self,
        scammer_input: str,
        detection_result: Optional[Dict[str, Any]] = None,
        insider_violation_result: Optional[Dict[str, Any]] = None,
        forced_mode: Optional[PersonaMode] = None
    ) -> Dict[str, Any]:
        """
        Generates a persona-adapted honeypot turn.
        
        Selection Logic:
        - If insider_violation_result has is_insider_violation == True (or forced_mode == CONFUSED_BANK_CUSTOMER):
          Sets mode to CONFUSED_BANK_CUSTOMER.
        - Otherwise defaults to DIGITAL_ARREST_VICTIM.
        """
        if forced_mode:
            self.mode = forced_mode
        elif insider_violation_result and insider_violation_result.get("is_insider_violation"):
            self.mode = PersonaMode.CONFUSED_BANK_CUSTOMER
        elif detection_result and detection_result.get("state") == "FRAUD":
            # Default to digital arrest victim for external scams unless mode was preset
            if self.mode != PersonaMode.CONFUSED_BANK_CUSTOMER:
                self.mode = PersonaMode.DIGITAL_ARREST_VICTIM

        decoy_context = self.entity_vault.get_decoy_context_string()

        # Update state machine turn & stage transition
        self.state_machine.turn_count += 1
        new_state = self.state_machine.determine_next_state(scammer_input, detection_result)
        self.state_machine.current_state = new_state

        victim_response = ""

        if self.mode == PersonaMode.CONFUSED_BANK_CUSTOMER:
            # Mode B: Confused Bank Customer
            # Attempt LLM generation or fallback to Bank Customer mock responses
            try:
                if self.state_machine.llm_client:
                    stage_key = new_state.value.lower()
                    stage_instr = BANK_CUSTOMER_STAGE_PROMPTS.get(stage_key, BANK_CUSTOMER_STAGE_PROMPTS["confused"])
                    system_prompt = f"{BANK_CUSTOMER_SYSTEM_PROMPT}\n\n{stage_instr}\n\nDECOY CREDENTIALS:\n{decoy_context}"
                    
                    messages = [{"role": "system", "content": system_prompt}]
                    for msg in self.state_machine.history:
                        messages.append({"role": msg["role"], "content": msg["content"]})
                    messages.append({"role": "user", "content": scammer_input})

                    victim_response = self.state_machine.llm_client.generate_response(
                        conversation_history=messages,
                        stage=new_state.value,
                        decoy_context=decoy_context,
                        mode=self.mode.value
                    )
            except Exception as e:
                logger.warning(f"LLM generation failed for Bank Customer persona ({e}). Using mock response.")
                victim_response = ""

            if not victim_response or "Simulated" in victim_response:
                victim_response = self.state_machine.llm_client.generate_mock_fallback(
                    stage=new_state.value,
                    mode=self.mode.value
                )

        else:
            # Mode A: Digital Arrest Victim
            honeypot_turn = self.state_machine.generate_honeypot_turn(
                scammer_input=scammer_input,
                detection_result=detection_result,
                decoy_context=decoy_context,
                mode=self.mode.value
            )
            victim_response = honeypot_turn.get("victim_response", "")

        # Record history
        self.state_machine.history.append({"role": "user", "content": scammer_input})
        self.state_machine.history.append({"role": "assistant", "content": victim_response})

        utility_score = self.state_machine.calculate_utility_score()

        return {
            "mode": self.mode.value,
            "state": new_state.value,
            "victim_response": victim_response,
            "turn_count": self.state_machine.turn_count,
            "utility_score": utility_score,
            "decoy_context": decoy_context
        }
