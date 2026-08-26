import csv
from datetime import datetime, timezone
from pathlib import Path


METRICS_DIR = Path(__file__).parent.parent / "metrics"
METRICS_FILE = METRICS_DIR / "detection_metrics.csv"

FIELDNAMES = [
    "timestamp_utc",
    "technique_id",
    "playbook",
    "rule_name",
    "event_time",
    "alert_time",
    "detection_latency_ms",
    "ai_response_time_ms",
    "ai_verdict",
    "ai_confidence",
    "ground_truth",
    "is_duplicate",
]


def _ensure_file() -> None:
    METRICS_DIR.mkdir(exist_ok=True)

    if not METRICS_FILE.exists():
        with open(METRICS_FILE, "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
            writer.writeheader()


def log_metric(
    technique_id: str,
    playbook: str,
    rule_name: str,
    event_time_epoch: float,
    alert_time_epoch: float,
    ai_response_time_ms: float,
    ai_verdict: str,
    ai_confidence: int,
    ground_truth: str = "",
    is_duplicate: bool = False,
) -> None:
    _ensure_file()

    detection_latency_ms = round(
        (alert_time_epoch - event_time_epoch) * 1000,
        2,
    )

    row = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "technique_id": technique_id,
        "playbook": playbook,
        "rule_name": rule_name,
        "event_time": event_time_epoch,
        "alert_time": alert_time_epoch,
        "detection_latency_ms": detection_latency_ms,
        "ai_response_time_ms": ai_response_time_ms,
        "ai_verdict": ai_verdict,
        "ai_confidence": ai_confidence,
        "ground_truth": ground_truth,
        "is_duplicate": is_duplicate,
    }

    with open(METRICS_FILE, "a", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writerow(row)
