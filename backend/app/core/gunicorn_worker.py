"""Gunicorn ASGI worker that leaves proxy attribution to the application."""

from uvicorn_worker import UvicornWorker


class HostUvicornWorker(UvicornWorker):
    # A trusted proxy is checked against the actual socket peer by the app.
    # Uvicorn must never rewrite that peer before the check.
    CONFIG_KWARGS = {"loop": "auto", "http": "auto", "proxy_headers": False}
