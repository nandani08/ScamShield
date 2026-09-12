import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from src.server.websocket import ws_router, IntegratedPipelineSession
from src.config import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ArrestShield.Server")

app = FastAPI(
    title="ArrestShield-Live",
    description="Real-time Multilingual Digital Arrest Scam Detection Engine & Interactive LLM Honeypot",
    version="1.0.0"
)

# Enable Cross-Origin Resource Sharing (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include WebSocket router
app.include_router(ws_router)

# Mount static directory if it exists
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Shared pipeline session for REST API requests
shared_api_session = IntegratedPipelineSession()


class TextAnalysisRequest(BaseModel):
    text: str
    reset_session: bool = False


@app.get("/")
async def root():
    """Serves the frontend dashboard index.html if available, or status JSON."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {
        "status": "online",
        "system": "ArrestShield-Live Scam Detection Engine",
        "version": "1.0.0",
        "endpoints": {
            "websocket_asr": settings.server.ws_asr_path,
            "status_check": "/api/status",
            "text_analysis": "/api/analyze_text"
        }
    }


@app.get("/api/status")
async def get_system_status() -> Dict[str, Any]:
    """Returns system status, active configuration parameters, and pipeline status."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "config": {
            "asr_model": settings.asr.asr_model_name,
            "detection_backbone": settings.detection.model_backbone,
            "safe_threshold": settings.detection.safe_threshold,
            "fraud_threshold": settings.detection.fraud_threshold,
            "llm_model": settings.honeypot.llm_model,
            "gliner_model": settings.extraction.gliner_model
        }
    }


@app.get("/api/decoy_credentials")
async def get_decoy_credentials() -> Dict[str, Any]:
    """Returns active synthetic decoy credentials from the Synthetic Entity Vault."""
    return shared_api_session.entity_vault.get_decoy_credentials()


@app.post("/api/analyze_text")
async def analyze_text_endpoint(payload: TextAnalysisRequest) -> Dict[str, Any]:
    """
    REST endpoint to analyze a dialogue text turn through the integrated pipeline:
    Tri-State Detection -> GLiNER Threat Extraction -> Adaptive LLM Honeypot.
    """
    if payload.reset_session or (payload.text and payload.text.strip().lower() == "reset"):
        shared_api_session.reset()
        if not payload.text or payload.text.strip().lower() == "reset":
            return {
                "status": "reset",
                "message": "Session reset successfully.",
                "detection": {
                    "state": "SAFE",
                    "risk_score": 0.0,
                    "prob_scam": 0.0,
                    "triggers": {"authority": 0.0, "urgency": 0.0, "isolation": 0.0, "payment_pressure": 0.0},
                    "predicted_stage": "monitoring",
                    "stage_id": 0,
                    "turns_in_window": 0
                },
                "honeypot": {
                    "active": False,
                    "mode": "digital_arrest_victim",
                    "state": "IDLE",
                    "victim_response": "",
                    "turn_count": 0,
                    "utility_score": 0.0
                }
            }

    if not payload.text or not payload.text.strip():
        raise HTTPException(status_code=400, detail="Text field cannot be empty.")

    return shared_api_session.process_text_turn(payload.text)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app:app",
        host=settings.server.host,
        port=settings.server.port,
        reload=False
    )
