import runpy
from pathlib import Path

import pytest

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
    else:
        assert "--force-send" not in command
        assert "--preview" in command
        assert not any(
            key in child for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "EMAIL_TO")
        )
        assert ("--dry-run" in command) == (mode == "fixtures")
        assert ("OPENAI_API_KEY" in child) == (mode == "preview")
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
