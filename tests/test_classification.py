import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from openai.types.responses import Response

from secdigest.classification import batch_classify, classify, client_from_env, parse_response, usage_record
from secdigest.evidence import validate_claims


def response(items, name="classify_clusters"):
    return Response.model_validate(
        {
            "id": "resp-test",
            "object": "response",
            "created_at": 1,
            "model": "gpt-5.4-mini",
            "status": "completed",
            "parallel_tool_calls": False,
            "tools": [],
            "tool_choice": "required",
            "output": [
                {
                    "type": "function_call",
                    "name": name,
                    "call_id": "call-test",
                    "arguments": json.dumps({"items": items} if name == "classify_clusters" else items),
                }
            ],
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "total_tokens": 30,
                "input_tokens_details": {"cached_tokens": 4, "cache_write_tokens": 0},
                "output_tokens_details": {"reasoning_tokens": 0},
            },
        }
    )


def test_invalid_output_retried_once(config, populated):
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    invalid = deepcopy(valid)
    invalid["industry_relevance"] = {}
    client = Mock()
    client.responses.create.side_effect = [response([invalid]), response([valid])]
    result = classify(config, populated, client=client)
    assert result["classified"] == 1
    assert client.responses.create.call_count == 2
    assert classify(config, populated, client=client)["classified"] == 0
    assert client.responses.create.call_count == 2


def test_second_invalid_output_fails(config, populated):
    with populated.db:
        populated.db.execute("DELETE FROM classifications")
    client = Mock()
    client.responses.create.return_value = response([])
    with pytest.raises(ValueError, match="twice"):
        classify(config, populated, client=client)
    assert client.responses.create.call_count == 2


@pytest.mark.parametrize("endpoint", ["https://api.openai.com/v1", "https://gateway.example.test/openai/v1"])
def test_responses_sdk_request_and_persistence(config, populated, respx_mock, monkeypatch, endpoint):
    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder")
    monkeypatch.setenv("OPENAI_BASE_URL", "  " + endpoint + "/  ")
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    model = config.settings["models"]["classification"]
    respx_mock.get(endpoint + "/models/" + model).mock(
        return_value=httpx.Response(
            200, json={"id": model, "object": "model", "created": 1, "owned_by": "openai"}
        )
    )
    route = respx_mock.post(endpoint + "/responses").mock(
        return_value=httpx.Response(200, json=response([valid]).model_dump())
    )
    with client_from_env() as client:
        result = classify(config, populated, client=client)
    assert result["classified"] == 1
    body = json.loads(route.calls[0].request.content)
    assert body["store"] is False
    assert body["parallel_tool_calls"] is False
    assert body["tool_choice"] == {"type": "function", "name": "classify_clusters"}
    assert body["tools"][0]["strict"] is True
    assert body["tools"][0]["parameters"]["additionalProperties"] is False
    assert "max_output_tokens" in body
    assert populated.clusters()[0]["classification"]["headline"] == valid["headline"]


@pytest.mark.parametrize("endpoint", [None, "", "  "])
def test_missing_or_blank_endpoint_uses_openai_default(monkeypatch, endpoint):
    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder")
    if endpoint is None:
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("OPENAI_BASE_URL", endpoint)
    with client_from_env() as client:
        assert str(client.base_url) == "https://api.openai.com/v1/"


@pytest.mark.parametrize(
    "endpoint",
    [
        "not-an-endpoint",
        "file:///private-placeholder",
        "https://user:private-placeholder@example.test/v1",
        "https://example.test/v1?token=private-placeholder",
        "https://example.test/v1#private-placeholder",
    ],
)
def test_invalid_endpoint_errors_do_not_expose_its_value(monkeypatch, endpoint):
    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder")
    monkeypatch.setenv("OPENAI_BASE_URL", endpoint)
    with pytest.raises(ValueError) as error:
        client_from_env()
    assert "OPENAI_BASE_URL" in str(error.value)
    assert "private-placeholder" not in str(error.value)


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


def test_openai_batch_resume_without_resubmission(config, populated):
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    client = Mock()
    client.files.create.return_value = SimpleNamespace(id="file-test")
    client.batches.create.return_value = SimpleNamespace(id="batch-test")
    submitted = batch_classify(config, populated, client=client)
    assert submitted["status"] == "pending"
    upload = client.files.create.call_args.kwargs
    request = json.loads(upload["file"][1].decode())
    assert request["url"] == "/v1/responses"
    assert request["body"]["tools"][0]["strict"] is True
    assert upload["purpose"] == "batch"
    client.batches.retrieve.return_value = SimpleNamespace(status="in_progress")
    assert batch_classify(config, populated, client=client)["status"] == "pending"
    assert client.batches.create.call_count == 1
    assert client.files.create.call_count == 1
    client.batches.retrieve.return_value = SimpleNamespace(
        status="completed", output_file_id="file-output", error_file_id=None
    )
    client.files.content.return_value = SimpleNamespace(
        text=json.dumps(
            {
                "custom_id": "group-0",
                "error": None,
                "response": {"status_code": 200, "body": response([valid]).model_dump()},
            }
        )
    )
    finished = batch_classify(config, populated, client=client)
    assert finished["status"] == "complete"
    assert finished["classified"] == 1
    assert finished["usage"][0]["batch"] is True
    client.responses.create.assert_not_called()


@pytest.mark.parametrize("status", ["failed", "expired", "cancelled"])
def test_failed_batches_leave_clusters_pending(config, populated, status):
    with populated.db:
        populated.db.execute("DELETE FROM classifications")
    client = Mock()
    client.files.create.return_value = SimpleNamespace(id="file-test")
    client.batches.create.return_value = SimpleNamespace(id="batch-test")
    batch_classify(config, populated, client=client)
    client.batches.retrieve.return_value = SimpleNamespace(
        status=status, output_file_id=None, error_file_id=None
    )
    result = batch_classify(config, populated, client=client)
    assert result["status"] == "partial"
    assert len(result["failures"]) == 3
    assert result["classified"] == 0


def test_usage_does_not_double_count_cached_tokens(config):
    actual = usage_record(config, response([]), "gpt-5.4-mini")
    assert actual["input_tokens"] == 6
    assert actual["cache_read_input_tokens"] == 4
    assert actual["estimated_usd"] == pytest.approx((6 * 0.75 + 4 * 0.075 + 20 * 4.5) / 1e6)
    batch = usage_record(config, response([]), "gpt-5.4-mini", batch=True)
    assert batch["estimated_usd"] == actual["estimated_usd"] / 2


@pytest.mark.parametrize("failure", ["incomplete", "refusal", "duplicate", "bad_json"])
def test_rejects_unusable_openai_output(config, populated, failure):
    cluster = populated.clusters()[0]
    output = response([cluster["classification"]])
    if failure == "incomplete":
        output.status = "incomplete"
    elif failure == "refusal":
        output.output = []
    elif failure == "duplicate":
        output.output *= 2
    else:
        output.output[0].arguments = "truncated {"
    with pytest.raises(ValueError):
        parse_response(config, output, [cluster], populated)


def test_weekly_synthesis_validates_references_and_reuses_cache(config, populated):
    from secdigest.synthesis import synthesize

    items = [c["classification"] for c in populated.clusters()]
    valid = synthesize(config, populated, items, "2026-W42", dry_run=True)
    valid = {k: v for k, v in valid.items() if k not in {"usage", "mode"}}
    invalid = deepcopy(valid)
    invalid["content_ideas"][0]["story_ids"] = ["invented"]
    client = Mock()
    client.responses.create.side_effect = [
        response(invalid, "weekly_synthesis"),
        response(valid, "weekly_synthesis"),
    ]
    result = synthesize(config, populated, items, "2026-W42", client=client)
    assert result["mode"] == "openai"
    assert client.responses.create.call_count == 2
    assert synthesize(config, populated, items, "2026-W42", client=client)["usage"] == []
    assert client.responses.create.call_count == 2
