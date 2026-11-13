"""Common request metadata and configured pagination validation."""

from ipaddress import IPv4Address, IPv6Address, ip_address

from fastapi import HTTPException, Request

from app.core.config import Settings

PeerIP = IPv4Address | IPv6Address


def request_peer_ip(request: Request) -> PeerIP:
    try:
        if request.client is None:
            raise ValueError("missing peer")
        return ip_address(request.client.host)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid request") from None


def page_size(settings: Settings, requested: int | None) -> int:
    size = settings.default_page_size if requested is None else requested
    if size <= 0 or size > settings.max_page_size:
        raise HTTPException(status_code=422, detail="Invalid request")
    return size
