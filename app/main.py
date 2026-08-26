import json
import time

from fastapi import FastAPI, Request

from app.ai_client import get_ai_verdict
from app.dedup import dedup_cache
from app.logging_config import logger
from app.metrics import log_metric


app = FastAPI(title="Detection Engineering Platform - Alert API")


def _normalize_payload(body: dict) -> dict:
    result = body.get("result", body)

    host = result.get("host") or result.get("ComputerName") or "unknown-host"
    user = result.get("User") or result.get("user") or "unknown-user"
    process = result.get("Image") or result.get("process") or "unknown-process"

    technique_id = result.get("technique_id") or "UNKNOWN"

    rule_name = (
        result.get("rule_name")
        or body.get("search_name")
        or "Unnamed Detection"
    )

    playbook = result.get("playbook") or "unspecified_playbook"

    event_time_epoch = result.get("event_time_epoch") or result.get("_time")

    try:
        event_time_epoch = float(event_time_epoch)
    except (TypeError, ValueError):
        event_time_epoch = time.time()

    baseline_context = result.get(
        "baseline_context",
        "No baseline context provided (Splunk default webhook payload).",
    )

    return {
        "host": host,
        "user": user,
        "process": process,
        "technique_id": technique_id,
        "rule_name": rule_name,
        "playbook": playbook,
        "event_time_epoch": event_time_epoch,
        "raw_fields": result,
        "baseline_context": baseline_context,
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "detection-engine-api",
    }


@app.post("/webhook/alert")
async def receive_alert(request: Request):
    raw_body = await request.body()

    try:
        body = json.loads(raw_body)
    except json.JSONDecodeError:
        logger.error("Webhook received non-JSON body — rejecting")
        return {
            "status": "error",
            "message": "Invalid JSON payload",
        }

    alert_dict = _normalize_payload(body)
    alert_time_epoch = time.time()

    logger.info(
        f"Alert received | technique={alert_dict['technique_id']} "
        f"| host={alert_dict['host']} "
        f"| rule={alert_dict['rule_name']}"
    )

    if dedup_cache.is_duplicate(alert_dict):
        logger.info(
            f"Duplicate alert suppressed | "
            f"technique={alert_dict['technique_id']}"
        )

        log_metric(
            technique_id=alert_dict["technique_id"],
            playbook=alert_dict["playbook"],
            rule_name=alert_dict["rule_name"],
            event_time_epoch=alert_dict["event_time_epoch"],
            alert_time_epoch=alert_time_epoch,
            ai_response_time_ms=0,
            ai_verdict="SUPPRESSED_DUPLICATE",
            ai_confidence=0,
            is_duplicate=True,
        )

        return {
            "status": "duplicate_suppressed",
            "message": "This alert was already processed within the dedup window.",
        }

    raw_alert_view = {
        "host": alert_dict["host"],
        "user": alert_dict["user"],
        "process": alert_dict["process"],
        "technique_id": alert_dict["technique_id"],
        "rule_name": alert_dict["rule_name"],
        "raw_fields": alert_dict["raw_fields"],
    }

    ai_result = get_ai_verdict(
        alert_dict,
        alert_dict["baseline_context"],
    )

    if ai_result.get("ai_available"):
        try:
            parsed = json.loads(ai_result["raw_text"])

            verdict = parsed.get("verdict", "UNKNOWN")
            confidence = parsed.get("confidence", 0)
            reasoning = parsed.get("reasoning", "")

        except (json.JSONDecodeError, KeyError):
            logger.warning(
                "AI response was not valid JSON — treating as unavailable"
            )

            verdict = "UNKNOWN - parse error"
            confidence = 0
            reasoning = ai_result["raw_text"][:200]

    else:
        verdict = ai_result["verdict"]
        confidence = ai_result["confidence"]
        reasoning = ai_result["reasoning"]

    enriched_alert_view = {
        **raw_alert_view,
        "ai_verdict": verdict,
        "ai_confidence": confidence,
        "ai_reasoning": reasoning,
        "ai_available": ai_result.get("ai_available", False),
    }

    log_metric(
        technique_id=alert_dict["technique_id"],
        playbook=alert_dict["playbook"],
        rule_name=alert_dict["rule_name"],
        event_time_epoch=alert_dict["event_time_epoch"],
        alert_time_epoch=alert_time_epoch,
        ai_response_time_ms=ai_result.get("response_time_ms", 0),
        ai_verdict=verdict,
        ai_confidence=confidence,
    )

    return {
        "status": "processed",
        "raw_alert": raw_alert_view,
        "ai_enriched_alert": enriched_alert_view,
        "ai_response_time_ms": ai_result.get("response_time_ms", 0),
    }
