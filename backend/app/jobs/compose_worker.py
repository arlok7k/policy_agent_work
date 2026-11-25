"""PB4 deployment entrypoint that registers the worker's incident mapping.

The API imports this mapping through its routers, but a standalone Celery
process does not. The response action's foreign key must be resolvable before
SQLAlchemy flushes a worker transition. The underlying Celery app and all
response semantics remain unchanged.
"""

from app.incidents.models import Incident as Incident
from app.jobs.worker import celery as celery
