"""Re-score an archived daily window offline and retain a row for every old story.

The source database is opened read-only and copied into memory. No classification,
collection, email, delivery-state or original-archive writes are performed.
"""

import argparse
import csv
import io
import json
import sqlite3
from datetime import datetime
from pathlib import Path

from secdigest.config import Config
from secdigest.rendering import archive
from secdigest.reporting import build_report
from secdigest.storage import Store


def review(config, original, database, destination):
    if Path(destination).resolve() == config.output:
        raise ValueError("Review output must be separate from the original archive directory")
    store = Store(":memory:")
    try:
        with sqlite3.connect(Path(database).resolve().as_uri() + "?mode=ro", uri=True) as source:
            source.backup(store.db)
        revised = build_report(config, store, "daily", now=datetime.fromisoformat(original["end"]))
    finally:
        store.close()
    if (revised["start"], revised["end"]) != (original["start"], original["end"]):
        raise ValueError("Review must preserve the exact original report window")
    original_ids = {
        ident for item in original["items"] for ident in item.get("merged_cluster_ids", [item["cluster_id"]])
    }
    revised_ids = {
        ident for item in revised["items"] for ident in item.get("merged_cluster_ids", [item["cluster_id"]])
    }
    if original_ids != revised_ids:
        raise ValueError(
            "Archive and database membership differ; use the database from the same archived run"
        )
    lookup = {
        ident: (rank, item)
        for rank, item in enumerate(revised["items"], 1)
        for ident in item.get("merged_cluster_ids", [item["cluster_id"]])
    }
    comparisons = []
    for rank, old in enumerate(original["items"], 1):
        new_rank, new = lookup[old["cluster_id"]]
        comparisons.append(
            {
                "headline": old["headline"],
                "cluster_id": old["cluster_id"],
                "new_cluster_id": new["cluster_id"],
                "old_rank": rank,
                "new_rank": new_rank,
                "old_importance": old["importance"],
                "new_importance": new["importance"],
                "old_priority": old["priority"],
                "new_priority": new["priority"],
                "old_location": old["location_relevance"],
                "new_location": new["location_relevance"],
                "old_industry": old["industry_relevance"],
                "new_industry": new["industry_relevance"],
                "old_practice": old["practice_area_relevance"],
                "new_practice": new["practice_area_relevance"],
                "adjustments": new["overrides"],
                "priority_breakdown": new["priority_breakdown"],
                "risk_evidence": new["risk_evidence"],
                "sources": old["sources"],
            }
        )
    config.settings["output"] = str(destination)
    archive(config, revised)
    destination = Path(destination)
    (destination / "comparison.json").write_text(
        json.dumps(comparisons, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    output = io.StringIO(newline="")
    fields = [
        "old_rank",
        "new_rank",
        "headline",
        "old_importance",
        "new_importance",
        "old_priority",
        "new_priority",
        "old_location",
        "new_location",
        "adjustments",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for row in comparisons:
        values = {
            key: json.dumps(row[key], ensure_ascii=False) if isinstance(row[key], (dict, list)) else row[key]
            for key in fields
        }
        writer.writerow(
            {
                key: "'" + value
                if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@"))
                else value
                for key, value in values.items()
            }
        )
    (destination / "comparison.csv").write_text(output.getvalue(), encoding="utf-8", newline="")
    return revised, comparisons


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report, rows = review(
        Config(), json.loads(args.report.read_text(encoding="utf-8")), args.database, args.output
    )
    print(
        json.dumps(
            {
                "reviewed": len(rows),
                "revised_items": len(report["items"]),
                "counts": report["counts"],
                "output": str(args.output),
            }
        )
    )


if __name__ == "__main__":
    main()
