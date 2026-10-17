import json

import httpx
import pytest
from openai import AuthenticationError

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
