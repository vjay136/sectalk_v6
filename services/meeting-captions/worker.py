"""Local-only inference endpoint for bounded 16 kHz mono PCM chunks."""

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import BoundedSemaphore

import numpy as np
from faster_whisper import WhisperModel


SAMPLE_RATE = 16_000
MAX_BYTES = SAMPLE_RATE * 2 * 6
LANGUAGES = frozenset(("en", "es", "fr", "de", "hi"))
TOKEN = os.environ["MEETING_CAPTIONS_WORKER_TOKEN"]
if len(TOKEN) < 24:
    raise ValueError("Configure a worker token with at least 24 characters")
MODEL = WhisperModel(os.environ["CAPTION_MODEL_PATH"], device="cpu", compute_type="int8",
                     local_files_only=True, cpu_threads=2, num_workers=1)
INFERENCE = BoundedSemaphore(1)


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass

    def result(self, status, body=None):
        payload = json.dumps(body or {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/transcribe":
            self.result(404)
            return
        if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + TOKEN):
            self.result(401)
            return
        language = self.headers.get("X-Source-Language")
        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            size = 0
        if language not in LANGUAGES or not 1000 <= size <= MAX_BYTES or size % 2:
            self.result(400)
            return
        if not INFERENCE.acquire(blocking=False):
            self.result(429)
            return
        try:
            body = self.rfile.read(size)
            if len(body) != size:
                self.result(400)
                return
            samples = np.frombuffer(body, dtype="<i2").astype(np.float32) / 32768
            if np.max(np.abs(samples)) < 0.008:
                self.result(200, {"text": ""})
                return
            pieces, _ = MODEL.transcribe(samples, language=language, beam_size=1, temperature=0,
                                         condition_on_previous_text=False, vad_filter=True, max_new_tokens=80)
            self.result(200, {"text": " ".join(piece.text.strip() for piece in pieces).strip()[:500]})
        except (ValueError, RuntimeError, OSError):
            self.result(503)
        finally:
            INFERENCE.release()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", int(os.environ.get("MEETING_CAPTIONS_WORKER_PORT", "3495"))), Handler)
    server.serve_forever()
