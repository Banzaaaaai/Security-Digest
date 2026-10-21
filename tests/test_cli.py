import json
import shutil
from pathlib import Path
from unittest.mock import Mock

import yaml

from secdigest.cli import main


def copy_config(tmp_path):
    root = Path(__file__).resolve().parents[1]
    shutil.copytree(root / "config", tmp_path / "config")


def test_dry_run_cannot_send_or_use_api(tmp_path, monkeypatch):
    copy_config(tmp_path)
    fail = Mock(side_effect=AssertionError("Network must not run"))
    monkeypatch.setattr("secdigest.cli.send", fail)
    monkeypatch.setattr("secdigest.cli.classify", fail)
    monkeypatch.setattr("secdigest.cli.ingest", fail)
    assert main(["--root", str(tmp_path), "--dry-run", "run-daily", "--force-send"]) == 0
    assert not fail.called
    assert not (tmp_path / "data/secdigest.sqlite").exists()
    assert (tmp_path / "output/samples/preview/secdigest-daily-2026-10-17.eml").exists()


def test_config_failure_still_records_status(tmp_path):
    assert main(["--root", str(tmp_path), "config", "check"]) == 1
    log = json.loads((tmp_path / "run_log.json").read_text())
    assert log[-1]["status"] == "failure"
    assert (tmp_path / "badge.json").exists()


def test_disabled_schedule_skips(tmp_path, capsys):
    copy_config(tmp_path)
    settings_path = tmp_path / "config/settings.yaml"
    settings = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    settings["scheduling"]["enabled"] = False
    settings_path.write_text(yaml.safe_dump(settings), encoding="utf-8")
    assert main(["--root", str(tmp_path), "schedule-guard", "daily"]) == 0
    assert capsys.readouterr().out.strip() == "false"
