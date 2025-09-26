from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse
from pathlib import Path
import json
import os

APP_NAME = "Bug Bounty AIO"
DEFAULT_SETTINGS_PATH = Path("/app/config/settings.json")

def load_settings(path: Path = DEFAULT_SETTINGS_PATH) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

settings = load_settings()
VERSION = settings.get("version", "0.1.0")
ENV = os.getenv("ENV", "prod")

app = FastAPI(title=APP_NAME, version=VERSION)

@app.get("/health", response_class=JSONResponse)
def health():
    # Fast, dependency-free liveness check
    return {"status": "ok"}

@app.get("/status", response_class=JSONResponse)
def status():
    # Slightly richer probe for dashboards
    return {
        "app": APP_NAME,
        "version": VERSION,
        "env": ENV,
        "settings_loaded": bool(settings),
    }

@app.get("/", response_class=PlainTextResponse)
def root():
    return f"{APP_NAME} v{VERSION} is running."

# Placeholder for future report endpoint; returns static stub for now
@app.get("/report", response_class=JSONResponse)
def report():
    # Later this will assemble recon results. For now, a stub.
    return {
        "domain": None,
        "modules": [],
        "summary": "Report pipeline placeholder. Add modules in Phase 8+."
    }
