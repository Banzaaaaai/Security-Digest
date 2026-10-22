import hashlib
import runpy
from pathlib import Path

import pytest

from secdigest.fixtures import FIXTURE_NOW, seed
from secdigest.reporting import build_report
from secdigest.storage import Store

review = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/review_scoring.py"))["review"]


def test_review_preserves_database_and_compares_every_original_story(config, tmp_path):
    database = tmp_path / "snapshot.sqlite"
    store = Store(database)
    seed(config, store)
    original = build_report(config, store, "daily", now=FIXTURE_NOW)
    store.close()
    checksum = hashlib.sha256(database.read_bytes()).hexdigest()
    report, rows = review(config, original, database, tmp_path / "review")
    assert len(rows) == len(original["items"])
    assert report["start"] == original["start"]
    assert report["end"] == original["end"]
    assert (tmp_path / "review/comparison.csv").exists()
    assert hashlib.sha256(database.read_bytes()).hexdigest() == checksum


def test_review_rejects_different_snapshot_or_original_output(config, populated, tmp_path):
    original = build_report(config, populated, "daily", now=FIXTURE_NOW)
    with pytest.raises(ValueError, match="separate"):
        review(config, original, tmp_path / "unused.sqlite", config.output)
    store = Store(tmp_path / "empty.sqlite")
    store.close()
    with pytest.raises(ValueError, match="membership"):
        review(config, original, tmp_path / "empty.sqlite", tmp_path / "review")
