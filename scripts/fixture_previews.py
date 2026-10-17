"""Generate clearly labelled previews; optionally accept reviewed golden files."""

import argparse
from pathlib import Path

from secdigest.config import Config
from secdigest.fixtures import FIXTURE_NOW, seed
from secdigest.rendering import archive, render_markdown
from secdigest.reporting import build_report
from secdigest.storage import Store

parser = argparse.ArgumentParser()
parser.add_argument("--update-golden", action="store_true")
args = parser.parse_args()
config = Config()
config.settings["output"] = "output/samples"
store = Store(":memory:")
seed(config, store)
for kind, period in (("daily", None), ("weekly", "2026-W42")):
    report = build_report(config, store, kind, period, FIXTURE_NOW, dry_run=True)
    paths = archive(config, report)
    print(paths["html"])
    if args.update_golden:
        target = Path("tests/golden")
        target.mkdir(exist_ok=True)
        (target / f"{kind}.md").write_text(render_markdown(config, report), encoding="utf-8")
