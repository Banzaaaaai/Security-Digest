import json

import httpx
import pytest
from openai import AuthenticationError, RateLimitError

from secdigest.operations import api_error_details, safe_trace


@pytest.mark.parametrize("code", ["invalid_api_key", "private-placeholder"])
def test_api_diagnostic_never_exposes_provider_message_or_unknown_code(code):
    response = httpx.Response(401, request=httpx.Request("GET", "https://api.openai.com/v1/models"))
    error = AuthenticationError(
        "Incorrect key: private-placeholder",
        response=response,
        body={"code": code, "message": "Incorrect key: private-placeholder"},
    )
    details = api_error_details(error)
    assert details["status_code"] == 401
    assert ("code" in details) == (code == "invalid_api_key")
    assert "private-placeholder" not in json.dumps(details) + safe_trace(error)


@pytest.mark.parametrize(
    "body,category",
    [
        ({"type": "insufficient_quota", "code": None}, "quota_exhausted"),
        ({"message": "You exceeded your current quota. private-placeholder"}, "quota_exhausted"),
        ({"code": "billing_hard_limit_reached"}, "billing_limit"),
        ({"error": {"message": "Rate limit reached for tokens per min. private-placeholder"}}, "rate_limit"),
        ({"message": "private-placeholder"}, None),
    ],
)
def test_distinguishes_quota_from_rate_limits_without_logging_response(body, category):
    response = httpx.Response(429, request=httpx.Request("POST", "https://api.openai.com/v1/responses"))
    error = RateLimitError("private-placeholder", response=response, body=body)
    details = api_error_details(error)
    assert details.get("category") == category
    assert "private-placeholder" not in json.dumps(details)
