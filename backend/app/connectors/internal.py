"""Simulated internal commands record intent only; they cause no real side effects."""

from typing import Literal

from app.connectors.base import Connector
from app.response.catalog import ActionDefinition


class InternalConnector(Connector):
    @property
    def name(self) -> Literal["internal"]:
        return "internal"

    def _command_name(self, definition: ActionDefinition) -> str:
        return definition.name
