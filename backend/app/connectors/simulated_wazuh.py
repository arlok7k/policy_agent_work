"""Wazuh-shaped command names recorded in the database, never sent anywhere."""

from typing import Literal

from app.connectors.base import Connector
from app.response.catalog import ActionDefinition


class SimulatedWazuhConnector(Connector):
    @property
    def name(self) -> Literal["simulated_wazuh"]:
        return "simulated_wazuh"

    def _command_name(self, definition: ActionDefinition) -> str:
        return "firewall_drop" if definition.name == "permanent_block" else definition.name
