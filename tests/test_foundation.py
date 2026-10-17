from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from secdigest.config import Config
from secdigest.fixtures import foundation_sample, seed
from secdigest.schemas import classification_model
from secdigest.storage import Store

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def config():
    return Config(ROOT)


def test_config_and_fixture_idempotence(config, tmp_path):
    store = Store(tmp_path / "test.sqlite")
    seed(config, store)
    seed(config, store)
    assert len(store.clusters()) == 12
    assert sum(len(c["articles"]) for c in store.clusters()) == 14
    assert len(config.industries) == 10
    assert len(config.practice_areas) == 11
    store.close()


@pytest.mark.parametrize("taxonomy", ["industries", "practice_areas"])
def test_schema_changes_with_taxonomy(config, taxonomy):
    modified = deepcopy(config)
    getattr(modified, taxonomy)["new_key"] = {"name": "New", "signals": "test"}
    schema = classification_model(modified).model_json_schema()
    model_name = "IndustryScores" if taxonomy == "industries" else "PracticeScores"
    assert "new_key" in schema["$defs"][model_name]["required"]


def test_schema_requires_exact_keys_and_bounded_scores(config):
    store = Store(":memory:")
    seed(config, store)
    item = store.clusters()[0]["classification"]
    item["industry_relevance"]["invented"] = 70
    with pytest.raises(ValidationError):
        classification_model(config).model_validate(item)
    del item["industry_relevance"]["invented"]
    item["location_relevance"][next(iter(config.regions))] = 101
    with pytest.raises(ValidationError):
        classification_model(config).model_validate(item)


def test_fixture_sample(config, tmp_path):
    config.settings["output"] = str(tmp_path)
    store = Store(":memory:")
    seed(config, store)
    path = foundation_sample(config, store)
    assert "not real news" in path.read_text(encoding="utf-8")
