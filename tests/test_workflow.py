import json
import runpy
from datetime import datetime
from pathlib import Path

import pytest
import yaml

invocation = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/workflow_digest.py"))[
    "invocation"
]


@pytest.mark.parametrize("kind", ["daily", "weekly"])
@pytest.mark.parametrize("mode", ["preview", "fixtures", "send"])
def test_workflow_delivery_modes(kind, mode):
    env = {
        "KIND": kind,
        "MODE": mode,
        "FORCE_SEND": "true",
        "OPENAI_API_KEY": "test-placeholder",
        "OPENAI_BASE_URL": "https://gateway.example.test/openai/v1",
        "SMTP_HOST": "smtp.example.test",
        "SMTP_PORT": "587",
        "SMTP_USER": "sender@example.test",
        "SMTP_PASSWORD": "test-placeholder",
        "EMAIL_TO": "recipient@example.test",
        "PERIOD": "test-period",
    }
    command, child = invocation(env)
    assert command[-2:] == ["--date" if kind == "daily" else "--week", "test-period"]
    if mode == "send":
        assert "--force-send" in command
        assert child["SMTP_PASSWORD"] == "test-placeholder"
        assert child["OPENAI_BASE_URL"] == env["OPENAI_BASE_URL"]
    else:
        assert "--force-send" not in command
        assert "--preview" in command
        assert not any(
            key in child for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "EMAIL_TO")
        )
        assert ("--dry-run" in command) == (mode == "fixtures")
        assert ("OPENAI_API_KEY" in child) == (mode == "preview")
        assert ("OPENAI_BASE_URL" in child) == (mode == "preview")
        if mode == "preview":
            assert child["OPENAI_BASE_URL"] == env["OPENAI_BASE_URL"]
    assert "SMTP_PASSWORD" in env  # Do not mutate the parent environment.


def test_live_workflow_requires_key_but_fixtures_do_not():
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        invocation({"KIND": "daily", "MODE": "preview"})
    assert "--dry-run" in invocation({"KIND": "daily", "MODE": "fixtures"})[0]


def test_workflow_rejects_unknown_modes():
    with pytest.raises(ValueError, match="Unknown"):
        invocation({"KIND": "daily", "MODE": "typo"})


def test_workflow_trims_surrounding_key_whitespace():
    _, child = invocation({"KIND": "daily", "MODE": "preview", "OPENAI_API_KEY": "  test-placeholder\n"})
    assert child["OPENAI_API_KEY"] == "test-placeholder"


@pytest.mark.parametrize(
    "key", ['"private-placeholder"', "OPENAI_API_KEY=private-placeholder", "private placeholder", "  "]
)
def test_workflow_rejects_malformed_key_without_exposing_it(key):
    with pytest.raises(ValueError) as error:
        invocation({"KIND": "daily", "MODE": "preview", "OPENAI_API_KEY": key})
    assert "private" not in str(error.value)
    assert "invalid formatting" in str(error.value)


@pytest.mark.parametrize(
    "kind,stamp,manual,allowed",
    [
        ("daily", "2026-10-20T09:48:57+00:00", False, True),
        ("daily", "2026-10-20T10:34:01+00:00", False, True),
        ("daily", "2026-10-20T04:30:00+00:00", False, False),
        ("daily", "2026-10-20T04:30:00+00:00", True, True),
        ("weekly", "2026-10-19T10:30:00+00:00", False, True),
        ("weekly", "2026-10-20T10:30:00+00:00", False, False),
    ],
)
def test_workflow_early_guard_accepts_delayed_jobs(kind, stamp, manual, allowed, monkeypatch, capsys):
    fixed = datetime.fromisoformat(stamp)

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return fixed.astimezone(tz)

    monkeypatch.setattr("datetime.datetime", FrozenDateTime)
    monkeypatch.setenv("KIND", kind)
    monkeypatch.setenv("MANUAL", str(manual).lower())
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/run-digest.yml").read_text(encoding="utf-8"))
    step = next(s for s in workflow["jobs"]["run"]["steps"] if s.get("id") == "hour")
    # Execute the actual embedded Python to cover the gate before dependency setup.
    script = "\n".join(step["run"].splitlines()[1:-1])
    exec(compile(script, "workflow-hour-guard", "exec"), {})
    assert capsys.readouterr().out.strip() == "run=" + str(allowed).lower()


def test_shared_workflow_requires_successful_story_grouping_check():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/run-digest.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["run"]["steps"]
    guard = next(s for s in steps if s.get("id") == "dedup")
    digest = next(s for s in steps if s.get("id") == "digest")
    assert steps.index(guard) < steps.index(digest)
    assert guard["run"] == "python scripts/check_digest_deduplication.py"
    assert "steps.dedup.outcome == 'success'" in digest["if"]
    for kind in ("daily", "weekly"):
        caller = yaml.safe_load((root / f".github/workflows/{kind}.yml").read_text(encoding="utf-8"))
        assert caller["jobs"]["digest"]["uses"] == "./.github/workflows/run-digest.yml"


@pytest.mark.parametrize("regression", [None, "no_merge", "overmerge", "lost_source", "lost_details"])
def test_workflow_story_grouping_gate_detects_regressions(config, monkeypatch, regression):
    root = Path(__file__).resolve().parents[1]
    verify = runpy.run_path(str(root / "scripts/check_digest_deduplication.py"))["verify"]
    fixture = json.loads((root / "tests/fixtures/deduplication-2026-10-23.json").read_text(encoding="utf-8"))
    if regression == "no_merge":
        monkeypatch.setattr("secdigest.reporting.deduplicate", lambda config, ranked: ranked)
    elif regression == "overmerge":
        from secdigest.deduplication import _merge

        monkeypatch.setattr(
            "secdigest.reporting.deduplicate", lambda config, ranked: [_merge(ranked, config)]
        )
    elif regression in {"lost_source", "lost_details"}:
        original = verify.__globals__["build_report"]

        def broken_report(*args, **kwargs):
            report = original(*args, **kwargs)
            if regression == "lost_source":
                report["items"][0]["sources"].pop()
            else:
                for item in report["items"]:
                    item["summary"] = "Complementary information was discarded."
            return report

        monkeypatch.setitem(verify.__globals__, "build_report", broken_report)
    if regression:
        with pytest.raises(RuntimeError, match="Story grouping regression"):
            verify(config, fixture)
    else:
        result = verify(config, fixture)
        assert result["status"] == "passed"
        assert result["input_clusters"] == result["source_urls_preserved"] == 15
        assert result["output_stories"] == 6
        assert result["duplicates_removed"] == 9
