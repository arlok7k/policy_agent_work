"""Accurate, versioned PB1/PB2 host OpenAPI security and error contracts."""

from http import HTTPStatus
from typing import Any

from fastapi import FastAPI

from app.auth.legacy_policy import load_legacy_policy
from app.auth.session import CSRF_COOKIE, CSRF_HEADER, SESSION_COOKIE

# Every registered host operation must be characterized explicitly. The
# operation names refer to the same versioned policy used by require_roles.
_ROLE_OPERATIONS: dict[tuple[str, str], str] = {
    ("get", "/api/alerts"): "alerts_read",
    ("get", "/api/alerts/stats/summary"): "alerts_read",
    ("get", "/api/alerts/{alert_id}"): "alerts_read",
    ("post", "/api/alerts/{alert_id}/investigate"): "investigate",
    ("get", "/api/incidents"): "incidents_read",
    ("post", "/api/incidents"): "incidents_write",
    ("get", "/api/incidents/{incident_id}"): "incidents_read",
    ("get", "/api/incidents/{incident_id}/evidence"): "incidents_read",
    ("post", "/api/threat-intel/check-ip"): "threat_intel",
    ("post", "/api/threat-intel/bulk-check"): "threat_intel",
    ("get", "/api/threat-intel/cache/stats"): "threat_intel",
    ("post", "/api/ai/summarize"): "ai",
    ("post", "/api/ai/recommendations"): "ai",
    ("post", "/api/ai/analyze-comprehensive"): "ai",
    ("get", "/api/users"): "users",
    ("post", "/api/users"): "users",
    ("patch", "/api/users"): "users",
    ("get", "/api/api-keys"): "api_keys",
    ("post", "/api/api-keys"): "api_keys",
    ("delete", "/api/api-keys"): "api_keys",
}
_COMMON = (400, 401, 403, 500, 503)
_ERRORS: dict[tuple[str, str], tuple[int, ...]] = {
    ("get", "/api/health"): (401, 500, 503),
    ("post", "/api/auth/login"): (*_COMMON, 429),
    ("get", "/api/auth/me"): (401, 500, 503),
    ("post", "/api/auth/logout"): _COMMON,
    ("post", "/api/auth/reauth"): (*_COMMON, 429),
    ("post", "/api/alerts/webhook"): (*_COMMON, 409, 413),
    ("get", "/api/alerts"): (*_COMMON, 422),
    ("get", "/api/alerts/stats/summary"): (401, 403, 500, 503),
    ("get", "/api/alerts/{alert_id}"): (*_COMMON, 404),
    ("post", "/api/alerts/{alert_id}/investigate"): (*_COMMON, 404, 422),
    ("get", "/api/incidents"): (*_COMMON, 422),
    ("post", "/api/incidents"): (*_COMMON, 404, 422),
    ("get", "/api/incidents/{incident_id}"): (*_COMMON, 404),
    ("get", "/api/incidents/{incident_id}/evidence"): (*_COMMON, 404, 422),
    ("post", "/api/threat-intel/check-ip"): _COMMON,
    ("post", "/api/threat-intel/bulk-check"): (*_COMMON, 422),
    ("get", "/api/threat-intel/cache/stats"): (401, 403, 500, 503),
    ("post", "/api/ai/summarize"): (*_COMMON, 404),
    ("post", "/api/ai/recommendations"): (*_COMMON, 404),
    ("post", "/api/ai/analyze-comprehensive"): (*_COMMON, 404),
    ("get", "/api/users"): (*_COMMON, 422),
    ("post", "/api/users"): (*_COMMON, 409, 422),
    ("patch", "/api/users"): (*_COMMON, 404, 409, 422),
    ("get", "/api/api-keys"): (*_COMMON, 422),
    ("post", "/api/api-keys"): (*_COMMON, 422),
    ("delete", "/api/api-keys"): (*_COMMON, 404),
}
_DESCRIPTIONS: dict[tuple[str, str], str] = {
    ("post", "/api/auth/login"): (
        "No session is required. If a live session cookie is sent, double-submit CSRF is required."
    ),
    ("post", "/api/alerts/webhook"): (
        "HMAC-SHA256 signs timestamp + '.' + canonical event UUID + '.' + the exact body bytes. "
        "The signature is sha256= followed by lowercase hex. Timestamp skew, replay reservations, "
        "body size and field lengths use the configured WEBHOOK_* bounds. A supplied session "
        "cookie is also subject to session and CSRF checks."
    ),
    ("get", "/api/alerts"): (
        "Exact-match filters and descending timestamp/UUID keyset pagination; "
        "DEFAULT_PAGE_SIZE and MAX_PAGE_SIZE bound each page."
    ),
    ("post", "/api/incidents"): (
        "Title and description use INCIDENT_MAX_TEXT_CHARS; distinct alert IDs use "
        "INCIDENT_MAX_ALERTS. All active legacy roles share the same tenant."
    ),
    ("post", "/api/alerts/{alert_id}/investigate"): (
        "Link or create an incident, append evidence and activity, and return mock enrichment. "
        "An absent indicator yields null intelligence; existing links may be reinvestigated."
    ),
    ("get", "/api/incidents"): (
        "Descending timestamp/UUID keyset pagination, bounded by DEFAULT_PAGE_SIZE and "
        "MAX_PAGE_SIZE."
    ),
    ("get", "/api/incidents/{incident_id}/evidence"): (
        "Evidence is scoped to the supplied incident, with descending timestamp/UUID keyset "
        "pagination bounded by DEFAULT_PAGE_SIZE and MAX_PAGE_SIZE."
    ),
    ("post", "/api/threat-intel/bulk-check"): (
        "Only deterministic mock results are available; THREAT_INTEL_BULK_MAX_ITEMS bounds input."
    ),
}


def _security_schemes() -> dict[str, dict[str, str]]:
    return {
        "SessionCookie": {"type": "apiKey", "in": "cookie", "name": SESSION_COOKIE},
        "CSRFCookie": {"type": "apiKey", "in": "cookie", "name": CSRF_COOKIE},
        "CSRFHeader": {"type": "apiKey", "in": "header", "name": CSRF_HEADER},
        "ServiceBearer": {"type": "http", "scheme": "bearer"},
        "WebhookTimestamp": {"type": "apiKey", "in": "header", "name": "X-Webhook-Timestamp"},
        "WebhookEventId": {"type": "apiKey", "in": "header", "name": "X-Webhook-Id"},
        "WebhookSignature": {"type": "apiKey", "in": "header", "name": "X-Webhook-Signature"},
    }


def _problem_schema() -> dict[str, Any]:
    return {
        "title": "Problem",
        "type": "object",
        "additionalProperties": False,
        "required": ["type", "title", "status", "code", "correlation_id"],
        "properties": {
            "type": {"type": "string", "const": "about:blank"},
            "title": {"type": "string"},
            "status": {"type": "integer", "minimum": 400, "maximum": 599},
            "code": {"type": "string", "pattern": "^GOV-HTTP-[45][0-9][0-9]$"},
            "correlation_id": {"type": "string", "format": "uuid"},
        },
    }


def _security(method: str, path: str) -> list[dict[str, list[str]]]:
    if path in {"/api/health", "/api/auth/login"}:
        return []
    if path == "/api/alerts/webhook":
        return [{"WebhookTimestamp": [], "WebhookEventId": [], "WebhookSignature": []}]
    if path == "/api/auth/me":
        return [{"SessionCookie": []}, {"ServiceBearer": []}]
    if method == "get":
        return [{"SessionCookie": []}]
    return [{"SessionCookie": [], "CSRFCookie": [], "CSRFHeader": []}]


class HostFastAPI(FastAPI):
    """Publish a contract matching the host's generic runtime error handler."""

    def openapi(self) -> dict[str, Any]:
        if self.openapi_schema is not None:
            return self.openapi_schema
        schema = super().openapi()
        # Do not leave an incomplete schema cached if characterization fails.
        self.openapi_schema = None
        components = schema.setdefault("components", {})
        definitions = components.setdefault("schemas", {})
        definitions.pop("HTTPValidationError", None)
        definitions.pop("ValidationError", None)
        definitions["Problem"] = _problem_schema()
        components["securitySchemes"] = _security_schemes()
        policy = load_legacy_policy()
        observed: set[tuple[str, str]] = set()
        for path, path_item in schema["paths"].items():
            for method, operation in path_item.items():
                if method not in {"get", "post", "patch", "put", "delete"}:
                    continue
                key = (method, path)
                observed.add(key)
                if key not in _ERRORS:
                    raise RuntimeError("Host OpenAPI operation is not characterized")
                responses = operation["responses"]
                # FastAPI normally assumes request validation is a 422 with a
                # different body; the installed handler actually returns 400.
                responses.pop("422", None)
                for code in sorted(_ERRORS[key]):
                    responses[str(code)] = {
                        "description": HTTPStatus(code).phrase,
                        "content": {
                            "application/problem+json": {
                                "schema": {"$ref": "#/components/schemas/Problem"}
                            }
                        },
                    }
                operation["security"] = _security(method, path)
                if key in _ROLE_OPERATIONS:
                    name = _ROLE_OPERATIONS[key]
                    if name not in policy:
                        raise RuntimeError("Host OpenAPI role operation is not configured")
                    operation["x-legacy-operation"] = name
                    operation["x-legacy-roles"] = list(policy[name])
                if key in _DESCRIPTIONS:
                    operation["description"] = _DESCRIPTIONS[key]
        if observed != set(_ERRORS):
            raise RuntimeError("Host OpenAPI characterization contains stale operations")
        self.openapi_schema = schema
        return schema
