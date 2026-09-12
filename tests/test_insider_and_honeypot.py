"""
Unit and Integration Tests for Rogue Insider Detector, Persona Adapter, and Decision Arbiter.
"""

import unittest
from src.rules.protocol_verifier import ProtocolVerifier
from src.honeypot.persona_adapter import HoneypotPersonaAdapter, PersonaMode
from src.orchestrator.decision_arbiter import DecisionArbiter


class TestInsiderProtocolAndHoneypot(unittest.TestCase):

    def setUp(self):
        self.verifier = ProtocolVerifier()
        self.persona_adapter = HoneypotPersonaAdapter()
        self.arbiter = DecisionArbiter()

    def test_protocol_verifier_separation_of_duties_violation(self):
        """Test Check 1: Branch Manager requesting an OTP triggers CRITICAL insider violation."""
        transcript = "Main Branch Manager bol raha hu, urgent account security update ke liye apna OTP share karo."
        result = self.verifier.verify_transcript(transcript)

        self.assertTrue(result["is_insider_violation"])
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(result["trigger_honeypot"])
        self.assertIn("branch manager", result["detected_role"].lower())
        self.assertIn("otp", result["detected_demands"])

    def test_protocol_verifier_state_inversion_violation(self):
        """Test Check 2: Insisting on live call verification without branch advisory triggers violation."""
        transcript = "Chief Manager speaking. Immediate account verification on this call right now or your card will be blocked."
        result = self.verifier.verify_transcript(transcript)

        self.assertTrue(result["is_insider_violation"])
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(result["trigger_honeypot"])

    def test_protocol_verifier_genuine_branch_advisory(self):
        """Test Genuine Call: Bank officer advising customer to visit physical branch is SAFE."""
        transcript = "Namaste, main Branch Manager speaking. Aapka KYC document update pending hai, please visit local branch with your Aadhar card."
        result = self.verifier.verify_transcript(transcript)

        self.assertFalse(result["is_insider_violation"])
        self.assertEqual(result["severity"], "NONE")
        self.assertFalse(result["trigger_honeypot"])

    def test_test_a_branch_manager_demands_otp_triggers_bank_customer_mode(self):
        """
        Test A: Branch Manager demands OTP -> Engine 1 flags CRITICAL -> Honeypot triggers in Bank Customer mode.
        """
        transcript = "Main Branch Manager speaking from SBI. Account suspend hone se bachane ke liye urgently OTP share karo."
        turn_result = self.arbiter.process_transcript_turn(transcript)

        # Assert Engine 1 violation
        engine1 = turn_result["engine1_insider_verifier"]
        self.assertTrue(engine1["is_insider_violation"])
        self.assertEqual(engine1["severity"], "CRITICAL")

        # Assert Honeypot Activation & Persona Mode B
        self.assertTrue(turn_result["trigger_honeypot"])
        honeypot = turn_result["honeypot"]
        self.assertTrue(honeypot["active"])
        self.assertEqual(honeypot["mode"], PersonaMode.CONFUSED_BANK_CUSTOMER.value)
        self.assertTrue(len(honeypot["victim_response"]) > 0)

    def test_test_b_fake_police_threatens_arrest_triggers_arrest_victim_mode(self):
        """
        Test B: Fake police officer threatens digital arrest -> Engine 2 flags FRAUD -> Honeypot triggers in Arrest Victim mode.
        """
        transcript = "Main Mumbai Police Cyber Cell se Officer Sharma speak kar raha hu (Badge #MH-4912). Warrant #CR-2024-8842 issued hai, immediate payment UPI rbi.verify@okicici par transfer karo or call 9876543210."
        turn_result = self.arbiter.process_transcript_turn(transcript)

        # Assert Honeypot Activation & Persona Mode A
        self.assertTrue(turn_result["trigger_honeypot"])
        honeypot = turn_result["honeypot"]
        self.assertTrue(honeypot["active"])
        self.assertEqual(honeypot["mode"], PersonaMode.DIGITAL_ARREST_VICTIM.value)
        self.assertTrue(len(honeypot["victim_response"]) > 0)

        # Assert Threat Extraction (GLiNER + Post-Processor)
        threats = turn_result["threat_extraction"]
        self.assertIn("rbi.verify@okicici", threats["upi_ids"])
        self.assertIn("MH-4912", threats["police_badge_ids"])

    def test_test_c_genuine_bank_manager_advises_branch_visit_evaluated_safe(self):
        """
        Test C: Genuine bank manager advises customer to visit local branch -> Evaluated as SAFE -> No honeypot.
        """
        transcript = "Namaste beta, main bank se Branch Head bol raha hu. Aapka passbook print ready hai, kripya visit local branch whenever convenient."
        turn_result = self.arbiter.process_transcript_turn(transcript)

        # Assert Engine 1 & Engine 2 evaluate as SAFE
        engine1 = turn_result["engine1_insider_verifier"]
        self.assertFalse(engine1["is_insider_violation"])

        engine2 = turn_result["engine2_external_detector"]
        self.assertEqual(engine2["state"], "SAFE")

        # Assert No Honeypot Triggered
        self.assertFalse(turn_result["trigger_honeypot"])
        self.assertFalse(turn_result["honeypot"]["active"])


if __name__ == "__main__":
    unittest.main()
