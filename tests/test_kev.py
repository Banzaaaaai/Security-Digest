import asyncio
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from secdigest.kev import parse_kev, refresh_kev
from secdigest.sources import Fetcher
from secdigest.storage import Store

NOW = datetime(2026, 10, 18, tzinfo=UTC)
PRIMARY = "https://cisa.test/kev.json"
MIRROR = "https://github.test/kev.json"


def catalog(released="2026-10-17T17:00:00Z"):
    return {
        "dateReleased": released,
        "catalogVersion": released[:10].replace("-", "."),
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-12345",
                "dateAdded": "2026-10-17",
                "dueDate": "2026-11-01",
                "vendorProject": "Example",
                "product": "Server",
                "requiredAction": "Upgrade.",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ],
    }


def setup(config):
    config.settings["http"]["per_host_delay"] = 0
    config.raw["feeds"]["enrichment"].update(cisa_kev_json=PRIMARY, cisa_kev_fallback_json=MIRROR)
    respx.get("https://cisa.test/robots.txt").respond(404)
    return Store(":memory:")


def refresh(config, store, now=NOW):
    async def check():
        async with Fetcher(config, store) as fetcher:
            return await refresh_kev(config, store, fetcher, now)

    return asyncio.run(check())


@respx.mock
def test_primary_success_304_and_refresh_interval(config):
    store = setup(config)
    primary = respx.get(PRIMARY).mock(
        side_effect=[
            httpx.Response(200, json=catalog(), headers={"ETag": "v1"}),
            httpx.Response(304),
        ]
    )
    assert refresh(config, store) == []
    snapshot = deepcopy(store.get("kev"))
    assert refresh(config, store, NOW + timedelta(hours=1)) == []
    assert primary.call_count == 1
    assert refresh(config, store, NOW + timedelta(hours=6)) == []
    assert primary.calls[1].request.headers["If-None-Match"] == "v1"
    assert store.get("kev") == snapshot
    assert store.get("kev:provenance")["source"] == PRIMARY


@pytest.mark.parametrize("failure", ["http", "malformed", "incomplete"])
@respx.mock
def test_official_mirror_fallback_on_primary_failure(config, failure):
    store = setup(config)
    response = httpx.Response(403)
    if failure == "malformed":
        response = httpx.Response(200, text="<html>not JSON</html>", headers={"ETag": "bad"})
    elif failure == "incomplete":
        response = httpx.Response(200, json={**catalog(), "count": 4}, headers={"ETag": "bad"})
    respx.get(PRIMARY).mock(return_value=response)
    respx.get("https://github.test/robots.txt").respond(404)
    respx.get(MIRROR).respond(200, json=catalog())
    assert "GitHub mirror" in refresh(config, store)[0]
    assert store.get("kev:provenance")["source"] == MIRROR
    assert store.get("kev:provenance")["count"] == 1
    assert store.get("http:" + PRIMARY) == {}
    assert "CVE-2026-12345" in store.get("kev")


@respx.mock
def test_both_sources_failed_retains_cache_and_retries(config):
    store = setup(config)
    respx.get("https://github.test/robots.txt").respond(404)
    primary = respx.get(PRIMARY).respond(200, json=catalog())
    assert refresh(config, store) == []
    snapshot = deepcopy(store.get("kev"))
    primary.respond(403)
    respx.get(MIRROR).respond(404)
    later = NOW + timedelta(hours=6)
    warnings = refresh(config, store, later)
    assert "all configured sources failed" in warnings[0]
    assert "cached data retained" in warnings[0]
    assert store.get("kev") == snapshot
    assert store.get("kev:checked") == NOW.isoformat()
    primary.respond(200, json=catalog())
    assert refresh(config, store, later + timedelta(minutes=1)) == []


@respx.mock
def test_stale_mirror_never_rolls_back_newer_catalog(config):
    store = setup(config)
    primary = respx.get(PRIMARY).respond(200, json=catalog())
    assert refresh(config, store) == []
    original = store.get("kev:provenance")
    primary.respond(403)
    respx.get("https://github.test/robots.txt").respond(404)
    respx.get(MIRROR).respond(200, json=catalog("2026-10-16T17:00:00Z"))
    assert "all configured sources failed" in refresh(config, store, NOW + timedelta(hours=6))[0]
    assert store.get("kev:provenance") == original


@respx.mock
def test_304_without_cached_snapshot_uses_mirror(config):
    store = setup(config)
    store.put("http:" + PRIMARY, {"etag": "orphaned"})
    primary = respx.get(PRIMARY).respond(304)
    respx.get("https://github.test/robots.txt").respond(404)
    respx.get(MIRROR).respond(200, json=catalog())
    assert "GitHub mirror" in refresh(config, store)[0]
    assert "If-None-Match" not in primary.calls[0].request.headers


@respx.mock
def test_source_switch_drops_stale_validators(config):
    store = setup(config)
    primary = respx.get(PRIMARY).respond(403)
    respx.get("https://github.test/robots.txt").respond(404)
    mirror = respx.get(MIRROR).respond(200, json=catalog(), headers={"ETag": "mirror-v1"})
    assert "GitHub mirror" in refresh(config, store)[0]
    # Primary recovers with a newer snapshot; its old validators must not be reused.
    store.put("http:" + PRIMARY, {"etag": "old-primary"})
    primary.respond(200, json=catalog("2026-10-18T01:00:00Z"), headers={"ETag": "primary-v2"})
    assert refresh(config, store, NOW + timedelta(hours=6)) == []
    assert "If-None-Match" not in primary.calls[1].request.headers
    assert mirror.call_count == 1
    assert store.get("kev:provenance")["source"] == PRIMARY
    assert store.get("http:" + PRIMARY)["etag"] == "primary-v2"


@pytest.mark.parametrize("mutation", ["count", "duplicate", "date", "missing-field", "naive"])
def test_catalog_validation_rejects_partial_or_invalid_data(mutation):
    value = catalog()
    if mutation == "count":
        value["count"] = 2
    elif mutation == "duplicate":
        value["vulnerabilities"] *= 2
        value["count"] = 2
    elif mutation == "date":
        value["vulnerabilities"][0]["dateAdded"] = "not-a-date"
    elif mutation == "missing-field":
        del value["vulnerabilities"][0]["requiredAction"]
    else:
        value["dateReleased"] = "2026-10-17T17:00:00"
    with pytest.raises(ValueError):
        parse_kev(json.dumps(value))
