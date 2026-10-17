"""Runtime classification schemas generated from configuration."""

from __future__ import annotations

from datetime import date
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, create_model

Score = Annotated[int, Field(strict=True, ge=0, le=100)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DetectionRef(StrictModel):
    type: Literal["sigma", "kql", "spl", "yara", "snort", "other"]
    url: str


def literal(keys):
    return Literal[tuple(keys)]


def score_model(name, keys):
    return create_model(name, __base__=StrictModel, **{key: (Score, ...) for key in keys})


def classification_model(config):
    regulation = create_model(
        "Regulation",
        __base__=StrictModel,
        key=(literal(config.regulations), ...),
        nature=(Literal["new", "amended", "enforcement", "guidance", "deadline"], ...),
        effective_or_deadline_date=(date | None, ...),
    )
    signal = create_model(
        "BusinessSignal",
        __base__=StrictModel,
        present=(bool, ...),
        type=(
            Literal["regulatory_deadline", "sector_campaign", "major_incident_wave", "technology_shift"],
            ...,
        ),
        sector=(literal(config.industries), ...),
        region=(literal(config.regions), ...),
        rationale=(str, ...),
    )
    return create_model(
        "Classification",
        __base__=StrictModel,
        cluster_id=(str, ...),
        headline=(Annotated[str, Field(min_length=1, max_length=120)], ...),
        summary=(Annotated[str, Field(min_length=1, max_length=1600)], ...),
        category=(literal(config.scoring["categories"]), ...),
        importance=(literal(config.scoring["importance_points"]), ...),
        importance_rationale=(str, ...),
        location_relevance=(score_model("LocationScores", config.regions), ...),
        countries_mentioned=(list[str], ...),
        industry_relevance=(score_model("IndustryScores", config.industries), ...),
        practice_area_relevance=(score_model("PracticeScores", config.practice_areas), ...),
        affected_technologies=(list[str], ...),
        cves=(list[str], ...),
        threat_actors=(list[str], ...),
        regulations=(list[regulation], ...),
        attack_techniques=(list[str], ...),
        detection_refs=(list[DetectionRef], ...),
        detection_coverage_note=(str, ...),
        related_case_studies=(Annotated[list[str], Field(max_length=2)], ...),
        business_signal=(signal, ...),
        recommended_action=(str, ...),
        confidence=(Annotated[float, Field(ge=0, le=1)], ...),
    )


def batch_model(config):
    return create_model(
        "Classifications", __base__=StrictModel, items=(list[classification_model(config)], ...)
    )
