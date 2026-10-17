from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from secdigest.classification import batch_classify, classify
from secdigest.evidence import validate_claims


def response(items):
    return SimpleNamespace(
        content=[SimpleNamespace(type="tool_use", name="classify_clusters", input={"items": items})],
        stop_reason="tool_use",
        usage=SimpleNamespace(input_tokens=10, output_tokens=20),
    )


def test_invalid_output_retried_once(config, populated):
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    invalid = deepcopy(valid)
    invalid["industry_relevance"] = {}
    client = Mock()
    client.messages.create.side_effect = [response([invalid]), response([valid])]
    result = classify(config, populated, client=client)
    assert result["classified"] == 1
    assert client.messages.create.call_count == 2
    assert classify(config, populated, client=client)["classified"] == 0
    assert client.messages.create.call_count == 2


def test_second_invalid_output_fails(config, populated):
    with populated.db:
        populated.db.execute("DELETE FROM classifications")
    client = Mock()
    client.messages.create.return_value = response([])
    with pytest.raises(ValueError, match="twice"):
        classify(config, populated, client=client)
    assert client.messages.create.call_count == 2


def test_unsupported_claims_are_dropped(config, populated):
    cluster = deepcopy(populated.clusters()[0])
    item = cluster["classification"]
    item.update(
        attack_techniques=["T9999", "T1566.001"],
        related_case_studies=["made-up"],
        detection_refs=[{"type": "sigma", "url": "https://invented.test/rule"}],
        cves=["CVE-2026-00000"],
    )
    populated.put("attack", ["T1566.001"])
    actual = validate_claims(config, item, cluster, populated)
    assert actual["attack_techniques"] == ["T1566.001"]
    assert actual["related_case_studies"] == []
    assert actual["detection_refs"] == []
    assert actual["cves"] == []


def test_business_signals_never_repeat_victim_targets(config, populated):
    config.settings["business_signals"]["enabled"] = True
    cluster = populated.clusters()[0]
    item = deepcopy(cluster["classification"])
    item["business_signal"].update(present=True, rationale="Sell remediation to breached Acme Bank")
    result = validate_claims(config, item, cluster, populated)
    assert "Acme" not in result["business_signal"]["rationale"]
    assert "Sector-level" in result["business_signal"]["rationale"]


def test_unsupported_regulation_date_is_removed(config, populated):
    cluster = deepcopy(populated.clusters()[4])
    cluster["classification"]["regulations"][0]["effective_or_deadline_date"] = "2026-11-01"
    result = validate_claims(config, cluster["classification"], cluster, populated)
    assert result["regulations"][0]["effective_or_deadline_date"] is None


def test_message_batch_resume_without_resubmission(config, populated):
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    client = Mock()
    client.messages.batches.create.return_value = SimpleNamespace(id="batch-test")
    submitted = batch_classify(config, populated, client=client)
    assert submitted["status"] == "pending"
    client.messages.batches.retrieve.return_value = SimpleNamespace(processing_status="in_progress")
    assert batch_classify(config, populated, client=client)["status"] == "pending"
    assert client.messages.batches.create.call_count == 1
    client.messages.batches.retrieve.return_value = SimpleNamespace(processing_status="ended")
    client.messages.batches.results.return_value = [
        SimpleNamespace(
            custom_id="group-0", result=SimpleNamespace(type="succeeded", message=response([valid]))
        )
    ]
    finished = batch_classify(config, populated, client=client)
    assert finished["status"] == "complete"
    assert finished["classified"] == 1
