import os
import json
import random
import logging
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional

from src.config import settings
from src.honeypot.prompts import build_honeypot_prompt

logger = logging.getLogger("ArrestShield.HoneypotLLMClient")


class HoneypotLLMClient:
    """
    LLM Client Wrapper supporting Ollama / vLLM local execution of Qwen2.5-7B-Instruct / Llama-3.1.
    
    Includes automatic graceful fallback to synthetic victim persona generator when local LLM server is offline.
    """
    def __init__(
        self,
        api_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout_sec: float = 0.1
    ):
        self.api_url = api_url if api_url is not None else settings.honeypot.llm_api_url
        self.model_name = model_name if model_name is not None else settings.honeypot.llm_model
        self.timeout_sec = timeout_sec

    def generate_mock_fallback(self, stage: str = "confused", mode: str = "digital_arrest_victim") -> str:
        """Generates realistic code-switched Hinglish victim responses based on persona mode."""
        if "bank" in mode.lower() or "insider" in mode.lower():
            stage_responses = {
                "confused": [
                    "Ji Manager Sahib, mera bank khata kyun block ho raha hai? Main toh pichhle 15 saal se aapki branch ka customer hu...",
                    "Ji sir, main samjha nahi... Kya mujhe mobile banking app open karni padegi account verify karne ke liye?",
                    "Branch Manager Sahib, main dukan par hu. Kya problem hui hai mere bank account mein?"
                ],
                "frightened": [
                    "Sir please mera account freeze mat kijiye! Meri beti ki college fee deni hai, main bilkul aapki help karunga sir!",
                    "Branch Head Sahib, main honest citizen hu. Mujhe bataiye mera account block hone se bachane ke liye kya karu?",
                    "Arre baap re! Account block mat karo sir, bataiye kya verify karna padega!"
                ],
                "cooperative": [
                    "Ji sir, main app open kar raha hu... Par yahan OTP SMS aane mein time lag raha hai, kya karna hai?",
                    "Ji Manager Sahib, main OTP enter karne ki koshish kar raha hu... Kya mujhe local branch aana padega?",
                    "Sir main aapke instructions follow kar raha hu. Konsa button click karu app mein?"
                ],
                "stalling": [
                    "Sir yahan network signal bohot weak hai... Aapka official Manager ID aur Branch IFSC code phir se boliye, main pen se note kar raha hu.",
                    "Sir SMS par OTP nahi aaya abhi tak... Aapka official landline number kya hai? Main call back karta hu.",
                    "Manager Sahib, app hang ho gayi hai... Aapka official employee ID number phir se slow-slow boliye please."
                ]
            }
        else:
            stage_responses = {
                "confused": [
                    "Sir main samjhaa nahi, mera Aadhar card crime se kaise link ho sakta hai? Main toh Nagpur mein dukan chalata hu...",
                    "Ji sir, kya baat kar rahe ho? Mera koi courier ya bank account illegal kaam mein nahi hai sir.",
                    "Sir aap konse department se bol rahe ho? Mujhe dar lag raha hai, kya problem hui hai?"
                ],
                "frightened": [
                    "Sir please arrest mat karo! Main ek honest taxpayer citizen hu sir, baap re... Mujhe batao police ko rokne ke liye kya karna hoga?",
                    "Officer Sharma ji, main bohot gareeb aadmi hu. Meri family ko mat batana, main bilkul cooperate karunga!",
                    "Arre sir arrest warrant cancel kar do please! Main jail nahi jana chahta, batao mujhe kya karna padega."
                ],
                "cooperative": [
                    "Ji sir, main abhi laptop aur phone ready kar raha hu. Aap jaisa bologe main waise hi process karunga.",
                    "Yes sir, main official clearance ke liye ready hu. Kya mujhe bank app open karni padegi?",
                    "Ji sir, main room ka door lock kar diya hai. Ab bataiye Aadhar clearance ke liye kya steps follow karu?"
                ],
                "stalling": [
                    "Sir yahan network signal bohot weak aa raha hai... Aapka official UPI ID aur account number phir se boliye, main copy-paste kar raha hu.",
                    "Sir main GPay open kiya hai par Error 404 dikha raha hai. Account number aur IFSC code ek baar slow-slow repeat karenge?",
                    "Ji sir, main pen dhundh raha hu... Aapka police badge ID number aur bank branch code kya hai? Dobara boliye please."
                ]
            }

        key = stage.lower()
        options = stage_responses.get(key, stage_responses["confused"])
        return random.choice(options)

    def generate_response(
        self,
        conversation_history: List[Dict[str, str]],
        stage: str = "confused",
        decoy_context: Optional[str] = None,
        mode: str = "digital_arrest_victim"
    ) -> str:
        """
        Sends chat completion request to local LLM server (Ollama/vLLM), falling back to mock generator if offline.
        """
        messages = build_honeypot_prompt(
            stage=stage,
            conversation_history=conversation_history,
            decoy_context=decoy_context
        )

        endpoint = f"{self.api_url.rstrip('/')}/chat/completions"
        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 150
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    content = data["choices"][0]["message"]["content"].strip()
                    logger.info(f"LLM Response generated via '{self.model_name}' endpoint.")
                    return content
        except Exception as e:
            logger.info(f"Local LLM server at '{endpoint}' offline or unreachable ({e}). Using synthetic honeypot fallback.")

        return self.generate_mock_fallback(stage=stage, mode=mode)

