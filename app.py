"""FastAPI chat application using a local LLM with OWASP-inspired security practices."""

from __future__ import annotations

import hashlib
import html
import logging
import os
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from dotenv import load_dotenv
from pydantic import BaseModel, constr
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

try:
    from llama_cpp import Llama
except ImportError as exc:  # pragma: no cover - dependency might be missing during tests
    raise RuntimeError("llama_cpp is required for this application") from exc

# Configure logging without storing sensitive user inputs
logger = logging.getLogger("chat_app")
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class ChatRequest(BaseModel):
    """Schema for incoming chat messages."""

    message: constr(min_length=1, max_length=500)


class ChatResponse(BaseModel):
    """Schema for outgoing chat responses."""

    response: str


# Load secrets from environment variables
load_dotenv()
API_KEY: Optional[str] = os.environ.get("API_KEY")
MODEL_PATH: Optional[str] = os.environ.get("LLM_MODEL_PATH")
ALLOWED_ORIGINS: list[str] = [o for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o]

if not MODEL_PATH:
    raise RuntimeError("Environment variable LLM_MODEL_PATH must be set.")

# Initialize the local LLM once at startup
llm: Llama = Llama(model_path=MODEL_PATH)

# Set up the FastAPI app with strict CORS policy
app = FastAPI(title="Secure Local LLM Chat")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST"],
    allow_headers=["Content-Type", "Authorization"],
)

# Rate limiter configuration
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    """Return 429 for rate limit violations without exposing internals."""
    return JSONResponse(status_code=429, content={"detail": "Too many requests"})

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_api_key(api_key_header: str = Depends(api_key_header)) -> str:
    """Validate provided API key against environment variable."""
    if API_KEY is None or api_key_header != API_KEY:
        logger.warning("Invalid API key attempt")
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key_header


def _log_message(msg: str) -> None:
    """Log only a hash and length of user messages."""
    hashed = hashlib.sha256(msg.encode("utf-8")).hexdigest()
    logger.info("Received message hash=%s length=%d", hashed, len(msg))


@app.post("/chat", response_model=ChatResponse)
@limiter.limit("5/minute")
async def chat(request_body: ChatRequest, request: Request, api_key: str = Depends(get_api_key)) -> ChatResponse:
    """Generate a response from the local LLM."""

    user_message = request_body.message
    _log_message(user_message)

    sanitized_input = html.escape(user_message)

    try:
        output = llm(
            sanitized_input,
            max_tokens=128,
            stop=["</s>"],
        )
    except Exception:  # pragma: no cover - log and hide details from users
        logger.exception("LLM generation failed")
        raise HTTPException(status_code=500, detail="Internal server error")

    text = output["choices"][0]["text"]
    safe_response = html.escape(text)
    return ChatResponse(response=safe_response)


@app.get("/health")
async def health() -> dict[str, str]:
    """Simple health check endpoint."""
    return {"status": "ok"}

