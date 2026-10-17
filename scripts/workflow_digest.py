"""Select an explicit delivery mode and strip credentials from preview subprocesses."""

import os
import subprocess
import sys
from pathlib import Path


def invocation(environ):
    env = dict(environ)
    kind, mode = env["KIND"], env.get("MODE", "preview")
    if kind not in {"daily", "weekly"} or mode not in {"send", "preview", "fixtures"}:
        raise ValueError("Unknown digest kind or mode")
    command = [sys.executable, "-m", "secdigest"]
    if mode == "fixtures":
        command += ["--dry-run", kind, "--preview"]
        env.pop("OPENAI_API_KEY", None)
    else:
        if not env.get("OPENAI_API_KEY"):
            raise ValueError("Set the OPENAI_API_KEY Actions secret, or use mode=fixtures")
        command += ["run-" + kind]
        if mode == "preview":
            command += ["--no-send", "--preview"]
        elif env.get("FORCE_SEND") == "true":
            command.append("--force-send")
    if mode != "send":
        for key in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "EMAIL_TO"):
            env.pop(key, None)
    if env.get("PERIOD"):
        command += ["--date" if kind == "daily" else "--week", env["PERIOD"]]
    return command, env


def main():
    try:
        command, env = invocation(os.environ)
        if (
            env.get("MODE") != "fixtures"
            and env.get("CACHE_DATABASE") == "true"
            and not Path("data/secdigest.sqlite").exists()
        ):
            raise ValueError("Database cache is unavailable. Restore a backup before resuming.")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return subprocess.call(command, env=env)


if __name__ == "__main__":
    sys.exit(main())
