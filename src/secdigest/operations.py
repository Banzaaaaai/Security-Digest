"""Atomic run history, alert suppression, safe errors and retention."""

import json
import traceback
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from openai import APIStatusError


def api_error_details(exc):
    """Allowlist API metadata; error messages and arbitrary provider values stay private."""
    if not isinstance(exc, APIStatusError):
        return {}
    details = {"provider": "openai", "status_code": exc.status_code}
    known_codes = {
        "invalid_api_key",
        "insufficient_quota",
        "rate_limit_exceeded",
        "model_not_found",
        "billing_hard_limit_reached",
        "billing_not_active",
        "quota_exceeded",
    }
    if isinstance(exc.code, str) and exc.code in known_codes:
        details["code"] = exc.code
    # Responses may supply the cause in `type` or message while leaving `code` empty.
    # Inspect in memory and emit only our fixed labels, never provider text.
    body = exc.body if isinstance(exc.body, dict) else {}
    if isinstance(body.get("error"), dict):
        body = body["error"]
    reason = " ".join(str(body.get(key, "")) for key in ("code", "type", "message")).lower()
    if exc.status_code == 429:
        if any(
            phrase in reason
            for phrase in (
                "insufficient_quota",
                "quota_exceeded",
                "current quota",
                "billing quota",
                "run out of credits",
                "insufficient credits",
                "no balance left",
                "credit balance",
            )
        ):
            details["category"] = "quota_exhausted"
        elif any(
            phrase in reason
            for phrase in (
                "billing_hard_limit_reached",
                "billing_not_active",
                "spend limit",
                "spending limit",
            )
        ):
            details["category"] = "billing_limit"
        elif any(
            phrase in reason
            for phrase in (
                "rate limit",
                "rate_limit",
                "tokens per min",
                "requests per min",
                "request too large",
            )
        ):
            details["category"] = "rate_limit"
    return details


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    temporary.replace(path)


def read_runs(root):
    path = root / "run_log.json"
    if not path.exists():
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise ValueError("run_log.json must contain a list")
    return value


def write_run(root, record):
    try:
        previous = read_runs(root)
    except (ValueError, OSError):
        # Preserve the damaged file for diagnosis rather than silently discarding it.
        path = root / "run_log.json"
        if path.exists():
            backup = root / "run_log.corrupt.json"
            if not backup.exists():
                backup.write_bytes(path.read_bytes())
        previous = []
    atomic_json(root / "run_log.json", [*previous, record][-365:])
    atomic_json(
        root / "badge.json",
        {
            "schemaVersion": 1,
            "label": "secdigest",
            "message": f"{record['status']} · {record['timestamp'][:10]}",
            "color": "brightgreen" if record["status"] == "success" else "red",
            "namedLogo": "github-actions",
        },
    )


def safe_trace(exc):
    frames = traceback.extract_tb(exc.__traceback__)[-6:]
    # Exception messages and source lines may contain response bodies or secrets.
    return "\n".join(
        [type(exc).__name__, *[f"{Path(f.filename).name}:{f.lineno} in {f.name}" for f in frames]]
    )


def source_health_due(config, store, now=None):
    now = now or datetime.now(UTC)
    health = store.get("source_health", {})
    last_new = store.get("last_new")
    no_recent = not last_new or now - datetime.fromisoformat(last_new) >= timedelta(hours=24)
    bad_ratio = not health.get("enabled") or health.get("failures", 0) / health["enabled"] > 0.3
    if not (no_recent or bad_ratio):
        return False
    for run in read_runs(config.root):
        events = run.get("emails", [run])
        for event in events:
            if event.get("email_type") == "source_health" and event.get("email_sent"):
                stamp = datetime.fromisoformat(event.get("timestamp", run["timestamp"]))
                if now - stamp < timedelta(days=config.settings["email"]["source_health_silence_days"]):
                    return False
    return True


def prune(config, store, now=None):
    now = now or datetime.now(UTC)
    store.prune(now - timedelta(days=config.settings["retention"]["database_days"]))
    folder = (config.output / "daily").resolve()
    if not folder.exists():
        return
    cutoff = now.date() - timedelta(days=config.settings["retention"]["daily_days"])
    for path in folder.iterdir():
        if (
            path.is_file()
            and path.suffix in {".md", ".html", ".json", ".csv"}
            and path.resolve().parent == folder
        ):
            try:
                old = date.fromisoformat(path.stem) < cutoff
            except ValueError:
                continue
            if old:
                path.unlink()
