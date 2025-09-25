from fastapi import FastAPI
from pydantic import BaseModel
import os

APP_VERSION = os.getenv("APP_VERSION", "0.1.0")

app = FastAPI(
    title="Bug Bounty AIO Backend",
    version=APP_VERSION,
    description="Backend API for orchestrating recon tools and generating reports."
)

class HealthResponse(BaseModel):
    status: str
    version: str

@app.get("/", tags=["meta"])
def root():
    return {"message": "Bug Bounty AIO backend is alive. See /docs for API."}

@app.get("/health", response_model=HealthResponse, tags=["meta"])
def health():
    return HealthResponse(status="ok", version=APP_VERSION)

@app.get("/version", tags=["meta"])
def version():
    return {"version": APP_VERSION}
