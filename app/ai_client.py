import os
import time

import httpx
from dotenv import load_dotenv
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from app.logging_config import logger


load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-flash-latest")
GEMINI_URL = (
    f"https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

REQUEST_TIMEOUT_SECONDS = 10.0


class AIUnavailableError(Exception):
    """Raised when the AI call fails after all retries are exhausted."""


def _build_prompt(alert: dict, baseline_context: str) -> str:
    return f"""You are a SOC false-positive triage assistant.

Alert details:

- Host: {alert.get('host')}
- User: {alert.get('user')}
- Process: {alert.get('process')}
- Technique ID: {alert.get('technique_id')}
- Rule name: {alert.get('rule_name')}
- Raw fields: {alert.get('raw_fields')}

Environment baseline context:

{baseline_context}

Respond ONLY in this exact JSON format, no markdown, no preamble:

{{
  "verdict": "Likely False Positive" | "Likely True Positive",
  "confidence": <integer 0-100>,
  "reasoning": "<2-3 sentence explanation>"
}}
"""


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type(
        (httpx.TimeoutException, httpx.HTTPStatusError)
    ),
    reraise=True,
)
def _call_gemini(prompt: str) -> dict:
    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt,
                    }
                ]
            }
        ]
    }

    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": GEMINI_API_KEY,
    }

    with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        response = client.post(
            GEMINI_URL,
            json=payload,
            headers=headers,
        )

        if response.status_code == 429 or response.status_code >= 500:
            logger.warning(
                f"Gemini API transient error: status={response.status_code}"
            )
            response.raise_for_status()

        response.raise_for_status()

        return response.json()


def get_ai_verdict(alert: dict, baseline_context: str) -> dict:
    prompt = _build_prompt(alert, baseline_context)
    start = time.perf_counter()

    try:
        raw_response = _call_gemini(prompt)
        text = raw_response["candidates"][0]["content"]["parts"][0]["text"]
        elapsed_ms = round(
            (time.perf_counter() - start) * 1000,
            2,
        )

        logger.info(
            f"AI verdict received | "
            f"technique={alert.get('technique_id')} | "
            f"latency_ms={elapsed_ms}"
        )

        return {
            "ai_available": True,
            "raw_text": text,
            "response_time_ms": elapsed_ms,
        }

    except Exception as exc:
        elapsed_ms = round(
            (time.perf_counter() - start) * 1000,
            2,
        )

        logger.error(
            f"AI call failed after retries | "
            f"technique={alert.get('technique_id')} | "
            f"error={exc} | "
            f"elapsed_ms={elapsed_ms}"
        )

        return {
            "ai_available": False,
            "verdict": "UNKNOWN - AI unavailable",
            "confidence": 0,
            "reasoning": (
                "AI enrichment failed after 3 retry attempts. "
                "Raw alert forwarded to analyst without AI context."
            ),
            "response_time_ms": elapsed_ms,
        }
