"""Celery CLI entry point; settings and secrets are loaded only in the worker."""

from app.core.pb2_config import load_pb2_settings
from app.jobs.celery_app import create_celery

celery = create_celery(load_pb2_settings())
