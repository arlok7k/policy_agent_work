"""Common request metadata and configured pagination validation."""

from ipaddress import IPv4Address, IPv6Address, ip_address

from fastapi import Request

from app.core.config import Settings
from app.core.exceptions import BadRequest, SemanticError

PeerIP = IPv4Address | IPv6Address


def request_peer_ip(request: Request) -> PeerIP:
    try:
        if request.client is None:
            raise ValueError("missing peer")
        return ip_address(request.client.host)
    except ValueError:
        raise BadRequest() from None


def page_size(settings: Settings, requested: int | None) -> int:
    size = settings.default_page_size if requested is None else requested
    if size <= 0 or size > settings.max_page_size:
        raise SemanticError()
    return size
