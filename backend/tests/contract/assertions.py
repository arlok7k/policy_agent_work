"""Check actual HTTP responses against the committed OpenAPI schemas."""

from functools import cache
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from app.main import app
from tests.sensitive import Redacted, assert_not_disclosed


@cache
def _validator(method: str, path: str, status: int, media: str) -> Draft202012Validator:
    document = app.openapi()
    response = document["paths"][path][method.lower()]["responses"][str(status)]
    schema = response["content"][media]["schema"]
    root = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "components": document["components"],
        "allOf": [schema],
    }
    return Draft202012Validator(root, format_checker=FormatChecker())


def assert_response_contract(method: str, path: str, response: Any, *protected: Redacted) -> None:
    operation = app.openapi()["paths"][path][method.lower()]
    status = response.status_code
    assert str(status) in operation["responses"], f"undocumented status for {method} {path}"
    definition = operation["responses"][str(status)]
    assert_not_disclosed("Contract response", response.text, *protected)
    if "content" not in definition:
        assert response.content == b""
        return
    media = response.headers["content-type"].split(";", 1)[0]
    assert media in definition["content"], f"unexpected media type for {method} {path}"
    payload = response.json()
    # An API key is deliberately returned once. Validate its type but replace
    # its value before passing data to a validator that may render failures.
    if method == "POST" and path == "/api/api-keys" and status == 201:
        if not isinstance(payload.get("secret"), str):
            raise AssertionError("Issued API-key secret must be a string")
        protected_secret = Redacted(payload["secret"])
        payload["secret"] = str(protected_secret)
    _validator(method, path, status, media).validate(payload)
    if status >= 400:
        assert payload["status"] == status
        assert payload["code"] == f"GOV-HTTP-{status:03d}"
