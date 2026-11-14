import json
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import httpx2
import pytest
from anthropic import DefaultHttpxClient, PermissionDeniedError
from anthropic.types.beta import BetaMessage

from secdigest.classification import (
    FALLBACK_BETA,
    batch_classify,
    classify,
    client_from_env,
    parse_response,
    response_json,
    usage_record,
)
from secdigest.evidence import validate_claims


def message(payload, model="claude-opus-5-5", stop_reason="end_turn"):
    return BetaMessage.model_validate(
        {
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [
                {"type": "thinking", "thinking": "", "signature": "signature-test"},
                {"type": "text", "text": json.dumps(payload)},
            ],
            "stop_reason": stop_reason,
            "stop_sequence": None,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_read_input_tokens": 4,
                "cache_creation_input_tokens": 2,
            },
        }
    )


def classified(items, **kwargs):
    return message({"items": items}, **kwargs)


def mocked(client, handler):
    return client.with_options(http_client=DefaultHttpxClient(transport=httpx2.MockTransport(handler)))


def error(status, kind, text):
    return httpx2.Response(status, json={"type": "error", "error": {"type": kind, "message": text}})


def test_invalid_output_retried_once(config, populated):
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    invalid = deepcopy(valid)
    invalid["industry_relevance"] = {}
    client = Mock()
    client.beta.messages.create.side_effect = [classified([invalid]), classified([valid])]
    result = classify(config, populated, client=client)
    assert result["classified"] == 1
    assert client.beta.messages.create.call_count == 2
    assert classify(config, populated, client=client)["classified"] == 0
    assert client.beta.messages.create.call_count == 2


def test_second_invalid_output_fails(config, populated):
    with populated.db:
        populated.db.execute("DELETE FROM classifications")
    client = Mock()
    client.beta.messages.create.return_value = classified([])
    with pytest.raises(ValueError, match="twice"):
        classify(config, populated, client=client)
    assert client.beta.messages.create.call_count == 2


@pytest.mark.parametrize("endpoint", ["https://api.anthropic.com", "https://gateway.example.test/anthropic"])
@pytest.mark.parametrize("metadata_status", [200, 403])
def test_messages_sdk_request_and_persistence(config, populated, monkeypatch, endpoint, metadata_status):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-placeholder")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "  " + endpoint + "/  ")
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    model = config.settings["models"]["classification"]
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "GET":
            assert request.url.path.endswith("/v1/models/" + model)
            if metadata_status == 403:
                return error(403, "permission_error", "Model metadata access denied")
            return httpx2.Response(
                200,
                json={
                    "id": model,
                    "type": "model",
                    "display_name": "Claude",
                    "created_at": "2026-01-01T00:00:00Z",
                },
            )
        return httpx2.Response(200, json=classified([valid]).model_dump(mode="json"))

    with client_from_env() as base:
        result = classify(config, populated, client=mocked(base, handler))
    assert result["classified"] == 1
    post = requests[-1]
    assert str(post.url).startswith(endpoint + "/v1/messages")
    assert FALLBACK_BETA in post.headers["anthropic-beta"]
    body = json.loads(post.content)
    assert body["model"] == model
    assert body["fallbacks"] == "default"
    assert body["output_config"]["effort"] == config.settings["models"]["classification_effort"]
    assert body["output_config"]["format"]["type"] == "json_schema"
    # Constraints the API does not enforce move into descriptions; Pydantic still checks them.
    headline = body["output_config"]["format"]["schema"]["$defs"]["Classification"]["properties"]["headline"]
    assert "maxLength" not in headline and "maxLength: 120" in headline["description"]
    assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert "tools" not in body and "tool_choice" not in body
    assert populated.clusters()[0]["classification"]["headline"] == valid["headline"]


def test_generation_permission_denial_still_stops_classification(config, populated, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-placeholder")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.example.test/anthropic")
    with populated.db:
        populated.db.execute("DELETE FROM classifications")
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(request)
            return error(403, "permission_error", "Generation denied")
        return error(403, "permission_error", "Metadata denied")

    with client_from_env() as base, pytest.raises(PermissionDeniedError):
        classify(config, populated, client=mocked(base, handler))
    assert len(posts) == 1
    assert all(cluster["classification"] is None for cluster in populated.clusters())


@pytest.mark.parametrize("endpoint", [None, "", "  "])
def test_missing_or_blank_endpoint_uses_anthropic_default(monkeypatch, endpoint):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-placeholder")
    if endpoint is None:
        monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", endpoint)
    with client_from_env() as client:
        assert str(client.base_url).rstrip("/") == "https://api.anthropic.com"


def test_missing_key_points_to_offline_mode(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY.*--dry-run"):
        client_from_env()


@pytest.mark.parametrize("workspace", [None, "", "  wrkspc_01TestWorkspace  "])
def test_workspace_header_is_sent_only_when_configured(config, populated, monkeypatch, workspace):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-placeholder")
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    if workspace is None:
        monkeypatch.delenv("ANTHROPIC_WORKSPACE_ID", raising=False)
    else:
        monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", workspace)
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    sent = []

    def handler(request):
        sent.append(request.headers.get("anthropic-workspace-id"))
        if request.method == "GET":
            return error(403, "permission_error", "Model metadata access denied")
        return httpx2.Response(200, json=classified([valid]).model_dump(mode="json"))

    with client_from_env() as base:
        classify(config, populated, client=mocked(base, handler))
    expected = workspace.strip() if workspace and workspace.strip() else None
    assert sent and all(value == expected for value in sent)


@pytest.mark.parametrize("workspace", ["private-placeholder", "wrkspc_private placeholder", "'wrkspc_x'"])
def test_invalid_workspace_id_is_rejected_without_exposing_it(monkeypatch, workspace):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-placeholder")
    monkeypatch.setenv("ANTHROPIC_WORKSPACE_ID", workspace)
    with pytest.raises(ValueError) as error:
        client_from_env()
    assert "ANTHROPIC_WORKSPACE_ID" in str(error.value)
    assert "private" not in str(error.value) and "'wrkspc_x'" not in str(error.value)


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
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-placeholder")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", endpoint)
    with pytest.raises(ValueError) as error:
        client_from_env()
    assert "ANTHROPIC_BASE_URL" in str(error.value)
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


def test_batch_resume_without_resubmission(config, populated):
    cluster = populated.clusters()[0]
    valid = deepcopy(cluster["classification"])
    with populated.db:
        populated.db.execute("DELETE FROM classifications WHERE cluster_id=?", (cluster["id"],))
    client = Mock()
    client.messages.batches.create.return_value = SimpleNamespace(id="msgbatch-test")
    submitted = batch_classify(config, populated, client=client)
    assert submitted["status"] == "pending"
    [request] = client.messages.batches.create.call_args.kwargs["requests"]
    assert request["custom_id"] == "group-0"
    assert request["params"]["output_config"]["format"]["type"] == "json_schema"
    assert "fallbacks" not in request["params"]  # The Batches API rejects it.
    assert populated.get("batch_job")["provider"] == "anthropic"
    client.messages.batches.retrieve.return_value = SimpleNamespace(processing_status="in_progress")
    assert batch_classify(config, populated, client=client)["status"] == "pending"
    assert client.messages.batches.create.call_count == 1
    client.messages.batches.retrieve.return_value = SimpleNamespace(processing_status="ended")
    client.messages.batches.results.return_value = [
        SimpleNamespace(
            custom_id="group-0", result=SimpleNamespace(type="succeeded", message=classified([valid]))
        )
    ]
    finished = batch_classify(config, populated, client=client)
    assert finished["status"] == "complete"
    assert finished["classified"] == 1
    assert finished["usage"][0]["batch"] is True
    client.beta.messages.create.assert_not_called()


@pytest.mark.parametrize("outcome", ["errored", "expired", "canceled", "missing"])
def test_unsuccessful_batch_requests_leave_clusters_pending(config, populated, outcome):
    with populated.db:
        populated.db.execute("DELETE FROM classifications")
    client = Mock()
    client.messages.batches.create.return_value = SimpleNamespace(id="msgbatch-test")
    batch_classify(config, populated, client=client)
    keys = [r["custom_id"] for r in client.messages.batches.create.call_args.kwargs["requests"]]
    client.messages.batches.retrieve.return_value = SimpleNamespace(processing_status="ended")
    client.messages.batches.results.return_value = (
        []
        if outcome == "missing"
        else [SimpleNamespace(custom_id=key, result=SimpleNamespace(type=outcome)) for key in keys]
    )
    result = batch_classify(config, populated, client=client)
    assert result["status"] == "partial"
    assert len(result["failures"]) == 3
    assert result["classified"] == 0


def test_pending_openai_batch_must_be_resolved_before_migration(config, populated):
    populated.put("batch_job", {"id": "batch-old", "provider": "openai", "status": "pending"})
    client = Mock()
    with pytest.raises(ValueError, match="another provider"):
        batch_classify(config, populated, client=client)
    client.messages.batches.retrieve.assert_not_called()


def test_usage_prices_each_input_token_class_once(config):
    actual = usage_record(config, classified([]), "claude-opus-5-5")
    assert actual["input_tokens"] == 10
    assert actual["cache_read_input_tokens"] == 4
    assert actual["cache_creation_input_tokens"] == 2
    assert actual["estimated_usd"] == pytest.approx((10 * 4 + 4 * 0.2 + 2 * 5 + 20 * 20) / 1e6)
    batch = usage_record(config, classified([]), "claude-opus-5-5", batch=True)
    assert batch["estimated_usd"] == actual["estimated_usd"] / 2


def test_usage_is_priced_at_the_fallback_model_that_answered(config):
    actual = usage_record(config, classified([], model="claude-opus-4-8"), "claude-opus-5-5")
    assert actual["model"] == "claude-opus-4-8"
    assert actual["estimated_usd"] == pytest.approx((10 * 5 + 4 * 0.5 + 2 * 6.25 + 20 * 25) / 1e6)


def test_answer_after_server_side_fallback_is_parsed():
    response = SimpleNamespace(
        stop_reason="end_turn",
        content=[SimpleNamespace(type="fallback"), SimpleNamespace(type="text", text='{"items": []}')],
    )
    assert response_json(response) == {"items": []}


@pytest.mark.parametrize("failure", ["max_tokens", "refusal", "no_text", "bad_json"])
def test_rejects_unusable_model_output(config, populated, failure):
    cluster = populated.clusters()[0]
    output = classified([cluster["classification"]])
    if failure == "max_tokens":
        output.stop_reason = "max_tokens"
    elif failure == "refusal":
        output.stop_reason = "refusal"
        output.content = []
    elif failure == "no_text":
        output.content = output.content[:1]
    else:
        output.content[1].text = "truncated {"
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
    client.beta.messages.create.side_effect = [message(invalid), message(valid)]
    result = synthesize(config, populated, items, "2026-W42", client=client)
    assert result["mode"] == "claude"
    assert client.beta.messages.create.call_count == 2
    assert client.beta.messages.create.call_args.kwargs["fallbacks"] == "default"
    assert synthesize(config, populated, items, "2026-W42", client=client)["usage"] == []
    assert client.beta.messages.create.call_count == 2
