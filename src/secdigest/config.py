"""Load and validate the editable configuration; no taxonomy lives in Python."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

from .normalize import safe_url

FILES = (
    "settings",
    "feeds",
    "regions",
    "industries",
    "practice_areas",
    "watch_tech",
    "regulations",
    "case_studies",
    "writing",
    "scoring",
)


class Config:
    def __init__(self, root: Path | str = "."):
        self.root = Path(root).resolve()
        self.raw = {}
        for name in FILES:
            data = yaml.safe_load((self.root / "config" / f"{name}.yaml").read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError(f"config/{name}.yaml must be an object")
            self.raw[name] = data
        self.settings = self.raw["settings"]
        for name in (
            "regions",
            "industries",
            "practice_areas",
            "watch_tech",
            "regulations",
            "case_studies",
            "writing",
        ):
            setattr(self, name, self.raw[name][name])
        self.scoring = self.raw["scoring"]
        self.feeds = self.raw["feeds"]["feeds"]
        self.validate()

    def validate(self):
        ZoneInfo(self.settings["timezone"])
        for name in ("regions", "industries", "practice_areas", "regulations", "case_studies"):
            values = getattr(self, name)
            if not isinstance(values, dict) or not values:
                raise ValueError(f"{name} must be a nonempty mapping")
        if abs(sum(self.scoring["weights"].values()) - 1) > 1e-8:
            raise ValueError("Scoring weights must sum to 1")
        if any(v < 0 for v in self.scoring["weights"].values()):
            raise ValueError("Scoring weights cannot be negative")
        if set(self.scoring["priority_regions"]) - self.regions.keys():
            raise ValueError("Unknown priority region")
        if not self.scoring["priority_regions"]:
            raise ValueError("At least one priority region is required")
        if set(self.scoring["weights"]) != {"importance", "location", "industry", "practice"}:
            raise ValueError("Scoring weights require importance, location, industry and practice")
        bands = self.scoring["priority_bands"]
        if set(bands) != set(self.scoring["importance_points"]):
            raise ValueError("Priority bands must cover every importance level")
        previous = -1
        for level in sorted(bands, key=self.scoring["importance_points"].get):
            lower, upper = bands[level]
            if not (0 <= lower <= upper <= 100 and lower > previous):
                raise ValueError("Priority bands must be ordered, nonoverlapping and within 0-100")
            previous = upper
        exposure = self.scoring["exposure"]
        for profile in [exposure["watch_default"], exposure["worldwide_campaign"], *exposure["profiles"]]:
            if any(not 0 <= profile[key] <= 100 for key in ("location_floor", "industry_floor")):
                raise ValueError("Exposure relevance floors must be within 0-100")
            if not isinstance(profile["systemic"], bool):
                raise ValueError("Exposure systemic must be a boolean")
        for profile in exposure["profiles"]:
            if not profile["aliases"] or any(not alias.strip() for alias in profile["aliases"]):
                raise ValueError("Exposure profiles require nonempty aliases")
        for case in self.case_studies.values():
            if (
                case["industry"] not in self.industries
                or set(case["practice_areas"]) - self.practice_areas.keys()
            ):
                raise ValueError("Unknown case-study taxonomy reference")
        for reg in self.regulations.values():
            if reg["region"] != "all" and reg["region"] not in self.regions:
                raise ValueError("Unknown regulation region")
            if reg["industries"] != "all" and set(reg["industries"]) - self.industries.keys():
                raise ValueError("Unknown regulation industry")
            for milestone in reg["milestones"]:
                from datetime import date

                date.fromisoformat(str(milestone["date"]))
        names = [f["name"] for f in self.feeds]
        if len(set(names)) != len(names):
            raise ValueError("Feed names must be unique")
        for feed in self.feeds:
            if feed.get("entry_url_field", "link") not in {"link", "id"}:
                raise ValueError("Feed entry_url_field must be link or id")
            if feed.get("type") == "csaf":
                prefix = feed.get("document_base_url", "")
                if not safe_url(prefix) or not prefix.endswith("/") or not feed.get("independence_key"):
                    raise ValueError(
                        "CSAF feeds need a document directory URL and publisher independence key"
                    )
        if not 1 <= self.settings["enrichment"].get("kev_refresh_hours", 6) <= 24:
            raise ValueError("KEV refresh interval must be between 1 and 24 hours")
        if not 1 <= self.settings["models"]["batch_size"] <= 10:
            raise ValueError("Model batch size must be between 1 and 10")
        if not 1000 <= self.settings["email"]["max_html_bytes"] <= 90000:
            raise ValueError("Email HTML limit must be 1000-90000 bytes")
        for region in self.raw["regions"]["priority_countries"].values():
            if region not in self.regions:
                raise ValueError("Unknown priority country region")
        for article in self.writing.values():
            if set(article["tags"]) - (self.industries.keys() | self.practice_areas.keys()):
                raise ValueError("Unknown writing tag")

    @property
    def fingerprint(self):
        return hashlib.sha256(json.dumps(self.raw, sort_keys=True, default=str).encode()).hexdigest()

    @property
    def database(self):
        return self.root / self.settings["database"]

    @property
    def output(self):
        return self.root / self.settings["output"]

    def save_feeds(self):
        (self.root / "config" / "feeds.yaml").write_text(
            yaml.safe_dump(self.raw["feeds"], sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
