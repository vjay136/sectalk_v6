# Offline meeting captions worker

Run the worker on the same host as the Next.js server. It listens only on loopback, accepts one recognition job at a time, and uses a local multilingual Faster Whisper model. It holds audio in memory for inference. The application saves text for participants who granted consent.

Install from `requirements.txt` in a Python virtual environment. Provision a vetted multilingual CTranslate2 Whisper model on disk before starting the worker. The local test used `Systran/faster-whisper-tiny` with CPU INT8 inference.

Set `CAPTION_MODEL_PATH` to the model directory and set `MEETING_CAPTIONS_WORKER_TOKEN` to a random secret with at least 24 characters. Set `HF_HUB_OFFLINE=1` and start `python services/meeting-captions/worker.py`. The default port is 3495.

Configure the app with the same worker token, `MEETING_CAPTIONS_WORKER_URL=http://127.0.0.1:3495/transcribe`, and its server-side `MEETING_CAPTIONS_SERVICE_KEY`. The worker needs no Supabase or LiveKit credentials. The app uses LiveKit to confirm the sender's active participant and published microphone before and after inference.

The browser test in `tests/meeting-captions.e2e.mjs` runs against the configured local app. Provide distinct synthetic 16 kHz, mono, 16-bit WAV files in `SECTALK_CAPTION_HOST_WAV` and `SECTALK_CAPTION_GUEST_WAV`. The host fixture includes “Welcome everyone to this meeting.” The guest fixture includes “I will prepare the report by Friday.”
