import json
import logging
from typing import Optional, Any, Dict
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from src.asr.streaming import StreamingASRProcessor
from src.detection.tristate_detector import TriStateDetector
from src.extraction.gliner_extractor import GLiNERThreatExtractor
from src.extraction.post_processor import ThreatPostProcessor
from src.honeypot.state_machine import HoneypotStateMachine
from src.honeypot.entity_vault import SyntheticEntityVault
from src.config import settings

from src.rules.protocol_verifier import ProtocolVerifier
from src.honeypot.persona_adapter import HoneypotPersonaAdapter, PersonaMode

logger = logging.getLogger("ArrestShield.WebSocket")
router = APIRouter()
ws_router = router


class IntegratedPipelineSession:
    """
    Manages state for an active streaming conversation session:
    ASR -> Dual-Engine Detection (Insider Protocol + Tri-State MuRIL) -> GLiNER Extraction -> Dual-Persona Honeypot.
    """
    def __init__(
        self,
        asr_processor: Optional[StreamingASRProcessor] = None,
        detector: Optional[TriStateDetector] = None,
        extractor: Optional[GLiNERThreatExtractor] = None,
        post_processor: Optional[ThreatPostProcessor] = None,
        honeypot_machine: Optional[HoneypotStateMachine] = None,
        entity_vault: Optional[SyntheticEntityVault] = None,
        verifier: Optional[ProtocolVerifier] = None,
        persona_adapter: Optional[HoneypotPersonaAdapter] = None
    ):
        self.asr_processor = asr_processor if asr_processor else StreamingASRProcessor(
            sample_rate=settings.asr.sample_rate,
            window_duration_sec=settings.asr.window_duration_sec,
            latency_target_ms=settings.asr.latency_target_ms
        )
        self.detector = detector if detector else TriStateDetector(model_name="dummy")
        self.extractor = extractor if extractor else GLiNERThreatExtractor(model_name="dummy")
        self.post_processor = post_processor if post_processor else ThreatPostProcessor()
        self.honeypot_machine = honeypot_machine if honeypot_machine else HoneypotStateMachine()
        self.entity_vault = entity_vault if entity_vault else SyntheticEntityVault()
        self.verifier = verifier if verifier else ProtocolVerifier()
        self.persona_adapter = persona_adapter if persona_adapter else HoneypotPersonaAdapter(
            state_machine=self.honeypot_machine,
            entity_vault=self.entity_vault
        )

        self.cumulative_extracted_entities: Dict[str, Any] = {
            "upi_ids": [],
            "phone_numbers": [],
            "urls": [],
            "police_badge_ids": [],
            "case_ids": [],
            "claimed_agencies": [],
            "total_valid_threat_indicators": 0
        }

    def reset(self):
        """Resets all pipeline session buffers."""
        self.asr_processor.reset()
        self.detector.reset()
        self.honeypot_machine.reset()
        self.entity_vault.reset_active_decoys()
        self.persona_adapter.reset()
        self.cumulative_extracted_entities = {
            "upi_ids": [],
            "phone_numbers": [],
            "urls": [],
            "police_badge_ids": [],
            "case_ids": [],
            "claimed_agencies": [],
            "total_valid_threat_indicators": 0
        }

    def process_text_turn(self, transcript_text: str, timestamp_ms: int = 0) -> Dict[str, Any]:
        """
        Executes complete end-to-end analysis on a text turn through Dual-Engine Pipeline.
        """
        # 1. Engine 1: Protocol Verifier (Rogue Insider Detection)
        verifier_result = self.verifier.verify_transcript(transcript_text)

        # 2. Engine 2: Tri-State ML Detection (External Scam Classification)
        detection_result = self.detector.process_turn(transcript_text)

        # 3. Zero-Shot Threat Extraction
        raw_entities = self.extractor.predict_entities(transcript_text)
        threat_report = self.post_processor.extract_and_validate_all(transcript_text, raw_entities)

        # Update cumulative threat indicators
        for key in ["upi_ids", "phone_numbers", "urls", "police_badge_ids", "case_ids", "claimed_agencies"]:
            existing_set = set(self.cumulative_extracted_entities[key])
            existing_set.update(threat_report[key])
            self.cumulative_extracted_entities[key] = sorted(list(existing_set))

        self.cumulative_extracted_entities["total_valid_threat_indicators"] = sum(
            len(self.cumulative_extracted_entities[k]) for k in ["upi_ids", "phone_numbers", "urls", "police_badge_ids", "case_ids", "claimed_agencies"]
        )

        # 4. Adaptive Dual-Engine Honeypot Activation
        is_insider_violation = verifier_result["is_insider_violation"]
        has_extracted_threats = threat_report.get("total_valid_threat_indicators", 0) > 0
        is_external_fraud = (
            detection_result["state"] == "FRAUD" 
            or (detection_result["state"] == "UNCERTAIN" and detection_result["risk_score"] >= 0.50)
            or has_extracted_threats
        )
        trigger_honeypot = is_insider_violation or is_external_fraud

        honeypot_payload = {
            "active": False,
            "mode": self.persona_adapter.mode.value,
            "state": "IDLE",
            "victim_response": "",
            "turn_count": self.honeypot_machine.turn_count,
            "utility_score": 0.0
        }

        if trigger_honeypot:
            target_mode = PersonaMode.CONFUSED_BANK_CUSTOMER if is_insider_violation else PersonaMode.DIGITAL_ARREST_VICTIM
            honeypot_turn = self.persona_adapter.generate_turn(
                scammer_input=transcript_text,
                detection_result=detection_result,
                insider_violation_result=verifier_result,
                forced_mode=target_mode
            )
            honeypot_payload = {
                "active": True,
                "mode": honeypot_turn["mode"],
                "state": honeypot_turn["state"],
                "victim_response": honeypot_turn["victim_response"],
                "turn_count": honeypot_turn["turn_count"],
                "utility_score": honeypot_turn["utility_score"]
            }

        return {
            "type": "analysis_turn",
            "transcript": transcript_text,
            "timestamp_ms": timestamp_ms,
            "engine1_insider_verifier": verifier_result,
            "detection": detection_result,
            "threat_extraction": threat_report,
            "cumulative_threats": self.cumulative_extracted_entities,
            "honeypot": honeypot_payload
        }


@router.websocket(settings.server.ws_asr_path)
async def websocket_asr_endpoint(websocket: WebSocket):
    """
    Streaming WebSocket endpoint for real-time speech transcription,
    Tri-State scam risk scoring, threat extraction, and adaptive LLM honeypot engagement.
    """
    await websocket.accept()
    logger.info(f"WebSocket client connected to endpoint '{settings.server.ws_asr_path}'")

    session: Optional[IntegratedPipelineSession] = None
    try:
        session = IntegratedPipelineSession()
    except Exception as e:
            logger.error(f"Failed to initialize IntegratedPipelineSession: {e}")
            await websocket.send_json({"type": "error", "message": f"Initialization error: {str(e)}"})
            await websocket.close(code=1011)
            return

    try:
        while True:
            message = await websocket.receive()

            # 1. Handle Binary Audio Frame (PCM)
            if "bytes" in message and message["bytes"]:
                binary_chunk = message["bytes"]
                asr_results = session.asr_processor.process_audio_chunk(binary_chunk)

                for asr_item in asr_results:
                    if asr_item.get("type") in ["transcript", "transcript_chunk"]:
                        transcript_text = asr_item.get("text", "")
                        timestamp_ms = asr_item.get("timestamp_ms", 0)
                        
                        # Process complete turn through pipeline
                        analysis_payload = session.process_text_turn(transcript_text, timestamp_ms=timestamp_ms)
                        await websocket.send_json(analysis_payload)
                    else:
                        await websocket.send_json(asr_item)

            # 2. Handle Text Control / Dialogue Frame (JSON)
            elif "text" in message and message["text"]:
                text_content = message["text"]
                try:
                    payload_json = json.loads(text_content)
                    action = payload_json.get("action")

                    if action == "reset":
                        session.reset()
                        await websocket.send_json({"type": "status", "status": "reset"})
                    elif action == "ping":
                        await websocket.send_json({"type": "pong"})
                    elif action == "analyze_text":
                        text_turn = payload_json.get("text", "")
                        analysis_payload = session.process_text_turn(text_turn)
                        await websocket.send_json(analysis_payload)
                    elif action == "flush":
                        flush_results = session.asr_processor.flush()
                        for asr_item in flush_results:
                            if asr_item.get("type") in ["transcript", "transcript_chunk"]:
                                transcript_text = asr_item.get("text", "")
                                analysis_payload = session.process_text_turn(transcript_text)
                                await websocket.send_json(analysis_payload)
                            else:
                                await websocket.send_json(asr_item)
                    else:
                        await websocket.send_json({"type": "info", "message": f"Received action '{action}'"})
                except json.JSONDecodeError:
                    await websocket.send_json({"type": "error", "message": "Invalid JSON text message received."})

    except (WebSocketDisconnect, RuntimeError):
        logger.info("WebSocket client disconnected from ArrestShield stream.")
    except Exception as e:
        logger.error(f"Error handling WebSocket stream: {e}", exc_info=True)
        try:
            await websocket.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        if session is not None:
            session.reset()
