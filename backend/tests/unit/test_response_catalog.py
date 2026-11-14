"""The response catalog is a stable, strictly typed simulated action ladder."""

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from app.response.catalog import CATALOG, catalog_page


def test_catalog_levels_modes_reversibility_and_schemas() -> None:
    expected = {
        "advisory": (0, "none", False, True, ("advisory",), None),
        "ioc_add": (1, "internal", False, True, ("automatic",), None),
        "ioc_update": (1, "internal", False, True, ("automatic",), None),
        "fp_mute": (1, "internal", False, True, ("automatic",), None),
        "escalate": (1, "internal", False, True, ("automatic",), None),
        "notify": (1, "internal", False, True, ("automatic",), None),
        "firewall_drop": (
            2,
            "simulated_wazuh",
            True,
            True,
            ("automatic", "manual"),
            "firewall_allow",
        ),
        "firewall_allow": (
            2,
            "simulated_wazuh",
            True,
            True,
            ("automatic", "manual"),
            "firewall_drop",
        ),
        "release_host": (2, "simulated_wazuh", False, False, (), None),
        "isolate_host": (3, "simulated_wazuh", True, True, ("manual",), "release_host"),
        "permanent_block": (3, "simulated_wazuh", False, True, ("manual",), None),
    }
    assert set(CATALOG) == set(expected)
    page = catalog_page()
    assert len(page.items) == len(expected)
    for item in page.items:
        assert (
            item.level,
            item.connector,
            item.reversible,
            item.requestable,
            tuple(item.execution_modes),
            item.reverse_action,
        ) == expected[item.action_type]
        assert item.ttl_required is (item.level == 2 and item.requestable)
        assert item.requires_unprotected_ip is (
            item.action_type in {"firewall_drop", "isolate_host", "permanent_block"}
        )
        Draft202012Validator.check_schema(item.target_schema)
        Draft202012Validator.check_schema(item.parameters_schema)
        assert item.target_schema["additionalProperties"] is False
        assert item.parameters_schema["additionalProperties"] is False
    with pytest.raises(TypeError):
        CATALOG["new"] = CATALOG["advisory"]  # type: ignore[index]


def test_catalog_validation_normalizes_ip_and_rejects_unknown_fields() -> None:
    action = CATALOG["firewall_drop"]
    target, params = action.validate_payload({"agent_id": "004", "ip": "2001:0db8::1"}, {})
    assert target == {"agent_id": "004", "ip": "2001:db8::1"}
    assert params == {}
    with pytest.raises(ValidationError):
        action.validate_payload({"agent_id": "004", "ip": "8.8.8.8", "unexpected": True}, {})
    with pytest.raises(ValidationError):
        action.validate_payload({"agent_id": "004", "ip": "8.8.8.8"}, {"command": "override"})
    with pytest.raises(ValidationError):
        action.validate_payload({"agent_id": "004", "ip": "not-an-address"}, {})
    with pytest.raises(ValidationError):
        CATALOG["isolate_host"].validate_payload({"agent_id": "004"}, {})
    with pytest.raises(ValidationError):
        CATALOG["notify"].validate_payload({"value": "team"}, {})
