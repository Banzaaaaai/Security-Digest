"""Command entry point. Dry runs are isolated and never call network providers."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path

from filelock import FileLock

from .classification import batch_classify, classify, fetch_internal_fulltext
from .config import Config
from .delivery import compose, digest_message, preview_message, send, send_failure_email, subject
from .enrichment import enrich
from .fixtures import FIXTURE_NOW, seed
from .operations import api_error_details, atomic_json, prune, safe_trace, source_health_due, write_run
from .rendering import archive
from .reporting import build_report
from .scheduling import schedule_allowed, window
from .sources import check_feeds, ingest
from .storage import Store

log = logging.getLogger(__name__)


def parser():
    p = argparse.ArgumentParser(
        prog="secdigest", description="Daily and weekly enterprise security intelligence"
    )
    p.add_argument("--root", default=".", help="Project root containing config/")
    p.add_argument(
        "--dry-run", action="store_true", help="Use synthetic fixtures, no network and no delivery"
    )
    sub = p.add_subparsers(dest="command")
    for name in ("ingest", "classify", "daily", "weekly", "run-daily", "run-weekly"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS)
        cmd.add_argument("--reclassify", action="store_true")
        cmd.add_argument("--batch-api", action="store_true")
        cmd.add_argument("--fetch-fulltext", action="store_true")
        if name not in {"ingest", "classify"}:
            cmd.add_argument("--week" if "weekly" in name else "--date", dest="period")
            delivery = cmd.add_mutually_exclusive_group()
            delivery.add_argument("--send", dest="send", action="store_true")
            delivery.add_argument("--no-send", dest="send", action="store_false")
            cmd.set_defaults(send=name.startswith("run-"))
            cmd.add_argument("--preview", action="store_true")
            cmd.add_argument("--force-send", action="store_true")
    for name, action in (("config", "check"), ("feeds", "check"), ("email", "test")):
        cmd = sub.add_parser(name)
        cmd.add_argument("action", choices=[action])
    guard = sub.add_parser("schedule-guard")
    guard.add_argument("kind", choices=["daily", "weekly"])
    guard.add_argument("--manual", action="store_true")
    return p


def print_json(value):
    print(json.dumps(value, ensure_ascii=True, indent=2, default=str))


def run(args, config, store, record):
    dry = args.dry_run
    now = FIXTURE_NOW if dry else datetime.now(UTC)
    command = args.command or "run-daily"
    record["stage"] = command
    if dry:
        seed(config, store)
    if command == "config":
        print_json(
            {
                "status": "valid",
                "regions": len(config.regions),
                "industries": len(config.industries),
                "practice_areas": len(config.practice_areas),
                "feeds": len(config.feeds),
            }
        )
        return
    if command == "feeds":
        if dry:
            print_json({"status": "skipped", "reason": "Dry run prohibits network access"})
            return
        result = asyncio.run(check_feeds(config, store))
        atomic_json(config.output / "source-check.json", result)
        print_json(result)
        return
    if command == "email":
        message = compose(
            "daily",
            "[SecDigest] Test email",
            "SecDigest SMTP delivery test.",
            "<html><body><p>SecDigest SMTP delivery test.</p></body></html>",
            preview=dry,
        )
        if dry:
            print(preview_message(config, message, "test"))
        else:
            event = {"email_type": "daily", "email_sent": False, "test": True}
            record["emails"].append(event)
            send(config, message)
            event["email_sent"] = True
            store.put("email_test_success", now.isoformat())
            print("Test email accepted by SMTP server.")
        return
    if not dry and command in {"ingest", "run-daily"}:
        record["stage"] = "feed validation"
        if any(not f.get("verified") for f in config.feeds):
            validation = asyncio.run(check_feeds(config, store))
            atomic_json(config.output / "source-check.json", validation)
        record["stage"] = "ingestion"
        record["ingestion"] = asyncio.run(ingest(config, store, now))
        record["stage"] = "enrichment"
        record["enrichment_warnings"] = asyncio.run(enrich(config, store, now))
    if not dry and command in {"classify", "run-daily"}:
        record["stage"] = "classification"
        candidates = (
            store.clusters(*window(config, "daily", getattr(args, "period", None), now)[:2])
            if command == "run-daily"
            else None
        )
        if getattr(args, "batch_api", False):
            result = batch_classify(config, store, args.reclassify, candidates=candidates)
        else:
            fulltext = (
                asyncio.run(
                    fetch_internal_fulltext(config, store, candidates, getattr(args, "reclassify", False))
                )
                if getattr(args, "fetch_fulltext", False)
                else None
            )
            result = classify(
                config, store, getattr(args, "reclassify", False), fulltext=fulltext, candidates=candidates
            )
        record["classification"] = result
        if result.get("status") == "pending":
            record["status"] = "pending"
            print_json(result)
            return
        if result.get("status") == "partial":
            raise RuntimeError(
                "Batch completed with failed requests; rerun classification for remaining clusters"
            )
    if command in {"ingest", "classify"}:
        print_json(
            record.get("ingestion", record.get("classification", {"fixture_clusters": len(store.clusters())}))
        )
        return
    kind = "weekly" if "weekly" in command else "daily"
    period = getattr(args, "period", None)
    if dry and kind == "weekly" and period is None:
        period = "2026-W42"
    record["stage"] = "reporting"
    report = build_report(config, store, kind, period, now, dry)
    paths = archive(config, report)
    record.update(period=report["period"], counts=report["counts"], items=len(report["items"]))
    print_json(
        {
            "artifacts": paths,
            "counts": report["counts"],
            "unclassified": report["unclassified"],
            "synthetic": dry,
        }
    )
    preview = getattr(args, "preview", False) or dry
    sending = getattr(args, "send", command.startswith("run-")) and not preview
    if preview or sending:
        message = digest_message(config, report, paths, preview=preview, now=now)
        if preview:
            print(preview_message(config, message, f"secdigest-{kind}-{report['period']}"))
        elif not report["items"] and not config.settings["email"]["send_when_empty"]:
            record["delivery_skipped"] = "Empty report; send_when_empty is false"
        elif store.was_sent(kind, report["period"]) and not getattr(args, "force_send", False):
            record["delivery_skipped"] = "Already sent for this period"
        else:
            record["stage"] = "email delivery"
            event = {"email_type": kind, "email_sent": False}
            record["emails"].append(event)
            send(config, message)
            store.mark_sent(kind, report["period"], now)
            event["email_sent"] = True
    if sending and source_health_due(config, store, now):
        record["stage"] = "source health alert"
        health = store.get("source_health", {})
        failures = health.get("failures", 0)
        message = compose(
            "source_health",
            subject("source_health", failures=failures),
            "Review the source-check report and failed feeds; collection coverage is degraded or no new items arrived in 24 hours.",
            "<html><body><p>Review the source-check report: collection coverage is degraded or no new items arrived in 24 hours.</p></body></html>",
        )
        event = {"email_type": "source_health", "email_sent": False}
        record["emails"].append(event)
        send(config, message)
        event["email_sent"] = True
    if not dry:
        record["stage"] = "retention"
        prune(config, store, now)


def main(argv=None):
    args = parser().parse_args(argv)
    if args.command is None and not args.dry_run:
        parser().print_help()
        return 0
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    started = time.monotonic()
    config, store = None, None
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "status": "success",
        "stage": "configuration",
        "emails": [],
        "synthetic": args.dry_run,
    }
    exit_code = 0
    finalized = False
    try:
        config = Config(args.root)
        if args.command == "schedule-guard":
            allowed = schedule_allowed(config, args.kind, manual=args.manual)
            print("true" if allowed else "false")
            return 0
        if args.dry_run:
            config.settings["output"] = "output/samples"
        lock_path = config.root / "data" / ("dry-run.lock" if args.dry_run else "secdigest.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(lock_path, timeout=1):
            store = Store(":memory:" if args.dry_run else config.database)
            store.put("last_classification_usage", [])
            store.put("last_synthesis_usage", [])
            try:
                run(args, config, store, record)
            except Exception as exc:
                record.update(status="failure", error=safe_trace(exc))
                log.error("Run failed at %s (%s)", record["stage"], type(exc).__name__)
                details = api_error_details(exc)
                if details:
                    record["api_error"] = details
                    log.error("API error: %s", json.dumps(details))
                # Only commands that requested delivery may send failure alerts.
                if (
                    not args.dry_run
                    and (getattr(args, "send", False) or args.command == "email")
                    and not getattr(args, "preview", False)
                ):
                    sent = send_failure_email(
                        config, record["stage"], record["error"], time.monotonic() - started
                    )
                    record["emails"].append({"email_type": "failure", "email_sent": sent})
                exit_code = 1
            finally:
                record["duration_s"] = round(time.monotonic() - started, 2)
                record["usage"] = [
                    *store.get("last_classification_usage", []),
                    *store.get("last_synthesis_usage", []),
                ]
                estimates = [u["estimated_usd"] for u in record["usage"]]
                record["estimated_usd"] = (
                    sum(estimates) if estimates and all(v is not None for v in estimates) else None
                )
                record["email_type"] = record["emails"][0]["email_type"] if record["emails"] else None
                record["email_sent"] = any(e["email_sent"] for e in record["emails"])
                write_run(config.output if args.dry_run else config.root, record)
                finalized = True
                store.close()
    except Exception as exc:
        log.error("Unable to start/finalize run (%s)", type(exc).__name__)
        if not finalized:
            record.update(
                status="failure", error=safe_trace(exc), duration_s=round(time.monotonic() - started, 2)
            )
            root = Path(args.root).resolve()
            try:
                write_run(root / "output" / "samples" if args.dry_run else root, record)
            except (ValueError, OSError):
                log.error("Unable to persist run status")
        exit_code = 1
    return exit_code
