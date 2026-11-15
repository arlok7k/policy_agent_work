"""Common request metadata and configured pagination validation."""

from ipaddress import IPv4Address, IPv6Address, ip_address

from fastapi import Request, Response

from app.core.config import Settings
from app.core.exceptions import BadRequest, SemanticError

PeerIP = IPv4Address | IPv6Address


def private_json(response: Response) -> None:
    """Prevent sensitive JSON from being cached or interpreted as HTML."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"


def request_peer_ip(request: Request) -> PeerIP:
    """Use one proxy-overwritten address only from an explicitly trusted peer.

    The ASGI server must not rewrite client addresses from forwarded headers.
    Untrusted peers cannot influence attribution using any forwarded header.
    """
    try:
        if request.client is None:
            raise ValueError("missing peer")
        peer = ip_address(request.client.host)
        settings: Settings = request.app.state.settings
        if peer not in settings.trusted_proxy_ips:
            return peer
        forwarded = request.headers.getlist("X-Forwarded-For")
        if len(forwarded) != 1 or "," in forwarded[0] or "%" in forwarded[0]:
            raise ValueError("missing or ambiguous forwarded address")
        return ip_address(forwarded[0].strip())
    except ValueError:
        raise BadRequest() from None


def page_size(settings: Settings, requested: int | None) -> int:
    size = settings.default_page_size if requested is None else requested
    if size <= 0 or size > settings.max_page_size:
        raise SemanticError()
    return size
