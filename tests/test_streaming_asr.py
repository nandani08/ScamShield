import warnings
warnings.filterwarnings("ignore")

import unittest
from unittest.mock import MagicMock, patch
import numpy as np
import json
import asyncio

from src.asr.streaming import StreamingASRProcessor
from src.server.websocket import websocket_asr_endpoint


class TestStreamingASRProcessor(unittest.TestCase):
    def setUp(self):
        # Create mock VAD and Transcriber
        self.mock_vad = MagicMock()
        self.mock_transcriber = MagicMock()
        
        # Configure default mock behaviors
        self.mock_vad.process_chunk.return_value = None
        self.mock_transcriber.transcribe.return_value = (
            "Aapka bank account freeze ho gaya hai",
            [{"start": 0.0, "end": 1.0, "text": "Aapka bank account freeze ho gaya hai", "probability": -0.1}]
        )

        self.processor = StreamingASRProcessor(
            vad_detector=self.mock_vad,
            transcriber=self.mock_transcriber,
            sample_rate=16000,
            window_duration_sec=2.0,
            latency_target_ms=800,
            min_speech_duration_sec=0.1  # lower for fast test triggers
        )

    def test_decode_chunk_int16(self):
        # Create 512 samples of int16 zeros
        int16_samples = np.zeros(512, dtype=np.int16)
        binary_data = int16_samples.tobytes()

        decoded = self.processor.decode_chunk(binary_data, dtype=np.int16)
        self.assertEqual(len(decoded), 512)
        self.assertEqual(decoded.dtype, np.float32)
        self.assertAlmostEqual(float(decoded[0]), 0.0)

    def test_decode_chunk_float32(self):
        float_samples = np.ones(256, dtype=np.float32) * 0.5
        binary_data = float_samples.tobytes()

        decoded = self.processor.decode_chunk(binary_data, dtype=np.float32)
        self.assertEqual(len(decoded), 256)
        self.assertEqual(decoded.dtype, np.float32)
        self.assertAlmostEqual(float(decoded[0]), 0.5)

    def test_process_audio_chunk_with_vad_speech(self):
        # Simulate VAD detecting speech start and end
        # 16000 Hz, 512 samples = 0.032s per chunk
        # We'll feed 4 chunks (2048 samples = 0.128s > 0.1s min speech threshold)
        int16_samples = np.random.randint(-1000, 1000, 2048, dtype=np.int16)
        binary_data = int16_samples.tobytes()

        # Set mock VAD to trigger speech start on frame 1 and speech end on frame 4
        self.mock_vad.process_chunk.side_effect = [
            {"start": 0},
            None,
            None,
            {"end": 2048}
        ]

        results = self.processor.process_audio_chunk(binary_data, dtype=np.int16)
        
        # Verify results returned a transcript payload
        self.assertGreaterEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["type"], "transcript")
        self.assertEqual(res["text"], "Aapka bank account freeze ho gaya hai")
        self.assertTrue(res["is_final"])
        self.assertIn("latency_ms", res)
        self.assertLess(res["latency_ms"], 800)  # Should complete under 800ms

    def test_flush_and_reset(self):
        # Add audio to speech buffer manually
        self.processor.speech_buffer = np.ones(3200, dtype=np.float32) * 0.1
        
        flush_results = self.processor.flush()
        self.assertEqual(len(flush_results), 1)
        self.assertEqual(flush_results[0]["text"], "Aapka bank account freeze ho gaya hai")
        self.assertTrue(flush_results[0]["is_final"])
        
        # Verify buffers reset
        self.assertEqual(len(self.processor.speech_buffer), 0)
        self.assertEqual(len(self.processor.audio_samples_buffer), 0)


class TestWebSocketHandler(unittest.TestCase):
    @patch("src.server.websocket.StreamingASRProcessor")
    def test_websocket_endpoint_control_flow(self, mock_processor_class):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        mock_proc = MagicMock()
        mock_proc.process_audio_chunk.return_value = [{
            "type": "transcript",
            "text": "Call CBI officer immediately",
            "is_final": False,
            "speech_detected": True,
            "latency_ms": 45.2,
            "segments": []
        }]
        mock_processor_class.return_value = mock_proc

        app = FastAPI()
        from src.server.websocket import router
        app.include_router(router)

        client = TestClient(app)
        
        with client.websocket_connect("/ws/asr") as websocket:
            # 1. Test sending control action ping
            websocket.send_text(json.dumps({"action": "ping"}))
            response = websocket.receive_json()
            self.assertEqual(response, {"type": "pong"})

            # 2. Test sending control action reset
            websocket.send_text(json.dumps({"action": "reset"}))
            response = websocket.receive_json()
            self.assertEqual(response, {"type": "status", "status": "reset"})
            mock_proc.reset.assert_called()

            # 3. Test sending binary audio chunk
            dummy_pcm = (np.zeros(1024, dtype=np.int16)).tobytes()
            websocket.send_bytes(dummy_pcm)
            response = websocket.receive_json()
            self.assertIn(response["type"], ["analysis_turn", "transcript"])
            transcript_text = response.get("transcript", response.get("text", ""))
            self.assertEqual(transcript_text, "Call CBI officer immediately")


if __name__ == "__main__":
    unittest.main()
