"""Fixed connector registry: the response catalog cannot instantiate real I/O."""

from collections.abc import Mapping
from types import MappingProxyType

from app.connectors.base import Connector
from app.connectors.internal import InternalConnector
from app.connectors.simulated_wazuh import SimulatedWazuhConnector

CONNECTORS: Mapping[str, Connector] = MappingProxyType(
    {"internal": InternalConnector(), "simulated_wazuh": SimulatedWazuhConnector()}
)
