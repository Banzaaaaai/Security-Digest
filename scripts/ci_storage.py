"""Limit commit-back to runtime artifacts; move large databases into Actions cache."""

import json
import os
import subprocess
import sys
from pathlib import Path

database = Path("data/secdigest.sqlite")
manifest = Path("data/storage-mode.json")
action = sys.argv[1]
previous = json.loads(manifest.read_text()) if manifest.exists() else {}
cached = previous.get("cache_database", False) or (database.exists() and database.stat().st_size > 50_000_000)
if action in {"inspect", "prepare"}:
    if action == "prepare":
        manifest.parent.mkdir(exist_ok=True)
        manifest.write_text(json.dumps({"cache_database": cached}, indent=2) + "\n")
        if cached:
            print(
                "::notice::Database storage uses Actions cache because the 50 MB threshold was reached.",
                file=sys.stderr,
            )
    print("cache_database=" + str(cached).lower())
elif action == "stage":
    paths = [p for p in ("output", "run_log.json", "badge.json", str(manifest)) if Path(p).exists()]
    if os.environ.get("CACHE_DATABASE") == "true":
        subprocess.run(["git", "rm", "--cached", "--ignore-unmatch", "--", str(database)], check=True)
    elif database.exists():
        paths.append(str(database))
    if paths:
        subprocess.run(["git", "add", "--", *paths], check=True)
