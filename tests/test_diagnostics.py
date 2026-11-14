import json

import httpx2
import pytest
from anthropic import APIStatusError, AuthenticationError

from secdigest.operations import api_error_details, safe_trace


def failed(status):
    return httpx2.Response(status, request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))


def body(kind, message):
    return {"type": "error", "error": {"type": kind, "message": message}}


@pytest.mark.parametrize("kind", ["authentication_error", "private-placeholder"])
def test_api_diagnostic_never_exposes_provider_message_or_unknown_type(kind):
    error = AuthenticationError(
        "Invalid key: private-placeholder",
        response=failed(401),
        body=body(kind, "Invalid key: private-placeholder"),
    )
    details = api_error_details(error)
    assert details["provider"] == "anthropic"
    assert details["status_code"] == 401
    assert ("code" in details) == (kind == "authentication_error")
    assert "private-placeholder" not in json.dumps(details) + safe_trace(error)


@pytest.mark.parametrize(
    "status,kind,message,category",
    [
        (
            400,
            "invalid_request_error",
            "Your credit balance is too low to access the Anthropic API. private-placeholder",
            "quota_exhausted",
        ),
        (402, "billing_error", "private-placeholder", "quota_exhausted"),
        (
            400,
            "invalid_request_error",
            "You have reached your specified API usage limits. private-placeholder",
            "billing_limit",
        ),
        (429, "rate_limit_error", "Exceeded your per-minute rate limit. private-placeholder", "rate_limit"),
        (529, "overloaded_error", "Overloaded. private-placeholder", "overloaded"),
        (400, "invalid_request_error", "private-placeholder", None),
    ],
)
def test_distinguishes_billing_from_rate_limits_without_logging_response(status, kind, message, category):
    error = APIStatusError("private-placeholder", response=failed(status), body=body(kind, message))
    details = api_error_details(error)
    assert details.get("category") == category
    assert details["code"] == kind
    assert "private-placeholder" not in json.dumps(details)
