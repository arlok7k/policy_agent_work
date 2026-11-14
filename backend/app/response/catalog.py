"""Single immutable action catalog and strict per-action payload models."""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

Level = Literal[0, 1, 2, 3]
Mode = Literal["advisory", "automatic", "manual"]
ConnectorName = Literal["none", "internal", "simulated_wazuh"]


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ValueTarget(StrictPayload):
    value: str = Field(min_length=1)


class FirewallTarget(StrictPayload):
    agent_id: str = Field(min_length=1)
    ip: IPvAnyAddress


class EmptyParameters(StrictPayload):
    pass


class MessageParameters(StrictPayload):
    message: str = Field(min_length=1)


class CatalogItem(BaseModel):
    action_type: str
    level: Level
    connector: ConnectorName
    reversible: bool
    requestable: bool
    execution_modes: list[Mode]
    ttl_required: bool
    reverse_action: str | None
    target_schema: dict[str, Any]
    parameters_schema: dict[str, Any]


class CatalogPage(BaseModel):
    items: list[CatalogItem]


@dataclass(frozen=True)
class ActionDefinition:
    name: str
    level: Level
    connector: ConnectorName
    reversible: bool
    requestable: bool
    modes: tuple[Mode, ...]
    target_model: type[StrictPayload]
    parameters_model: type[StrictPayload]
    reverse_action: str | None = None

    def view(self) -> CatalogItem:
        return CatalogItem(
            action_type=self.name,
            level=self.level,
            connector=self.connector,
            reversible=self.reversible,
            requestable=self.requestable,
            execution_modes=list(self.modes),
            ttl_required=self.level == 2 and self.requestable,
            reverse_action=self.reverse_action,
            target_schema=self.target_model.model_json_schema(),
            parameters_schema=self.parameters_model.model_json_schema(),
        )

    def validate_payload(
        self, target: dict[str, Any], parameters: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Return normalized structured data; unknown properties are rejected."""
        validated_target = self.target_model.model_validate(target)
        validated_parameters = self.parameters_model.model_validate(parameters)
        return (
            validated_target.model_dump(mode="json", exclude_none=True),
            validated_parameters.model_dump(mode="json", exclude_none=True),
        )


_DEFINITIONS = (
    ActionDefinition(
        "advisory", 0, "none", False, True, ("advisory",), ValueTarget, MessageParameters
    ),
    ActionDefinition(
        "ioc_add", 1, "internal", False, True, ("automatic",), ValueTarget, EmptyParameters
    ),
    ActionDefinition(
        "ioc_update", 1, "internal", False, True, ("automatic",), ValueTarget, EmptyParameters
    ),
    ActionDefinition(
        "fp_mute", 1, "internal", False, True, ("automatic",), ValueTarget, EmptyParameters
    ),
    ActionDefinition(
        "escalate", 1, "internal", False, True, ("automatic",), ValueTarget, MessageParameters
    ),
    ActionDefinition(
        "notify", 1, "internal", False, True, ("automatic",), ValueTarget, MessageParameters
    ),
    ActionDefinition(
        "firewall_drop",
        2,
        "simulated_wazuh",
        True,
        True,
        ("automatic", "manual"),
        FirewallTarget,
        EmptyParameters,
        "firewall_allow",
    ),
    ActionDefinition(
        "firewall_allow",
        2,
        "simulated_wazuh",
        True,
        True,
        ("automatic", "manual"),
        FirewallTarget,
        EmptyParameters,
        "firewall_drop",
    ),
    ActionDefinition(
        "release_host", 2, "simulated_wazuh", False, False, (), FirewallTarget, EmptyParameters
    ),
    ActionDefinition(
        "isolate_host",
        3,
        "simulated_wazuh",
        True,
        True,
        ("manual",),
        FirewallTarget,
        EmptyParameters,
        "release_host",
    ),
    ActionDefinition(
        "permanent_block",
        3,
        "simulated_wazuh",
        False,
        True,
        ("manual",),
        FirewallTarget,
        EmptyParameters,
    ),
)
CATALOG = MappingProxyType({item.name: item for item in _DEFINITIONS})
if len(CATALOG) != len(_DEFINITIONS):
    raise RuntimeError("Duplicate response action catalog entry")


def catalog_page() -> CatalogPage:
    return CatalogPage(items=[item.view() for item in CATALOG.values()])
