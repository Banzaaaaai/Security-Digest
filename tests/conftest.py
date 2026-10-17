from pathlib import Path

import pytest

from secdigest.config import Config
from secdigest.fixtures import seed
from secdigest.storage import Store


@pytest.fixture
def config():
    return Config(Path(__file__).resolve().parents[1])


@pytest.fixture
def populated(config):
    store = Store(":memory:")
    seed(config, store)
    yield store
    store.close()
