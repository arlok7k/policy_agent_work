# Implementation progress

Current phase: **PB1 — backend skeleton, database core, authentication**

| Task | Status | Notes |
|---|---|---|
| PB1-T01 | Done | `make lint test typecheck`: 2 tests passed; scans and pre-commit passed |
| PB1-T02 | Done | 10 configuration/startup tests; settings and secret-file failures are closed |
| PB1-T03 | Done | PostgreSQL 18.6 session/transaction tests and Alembic up/down passed |
| PB1-T04 | Done | Revisions 001–003, audit trigger/privileges, real up/down; 27 tests passed |
| PB1-T05 | In progress | Login/logout/me/reauth, rate limiting, cookies, CSRF |
| PB1-T06 | Pending | Current principal and legacy role guard |
| PB1-T07 | Pending | Admin users and session revocation |
| PB1-T08 | Pending | Admin API-key lifecycle and service identity |
| PB1-T09 | Pending | Problem responses, correlation and JSON logging |
| PB1-T10 | Pending | Health endpoint |
| PB1-T11 | Pending | Environment-protected development seed |

**Blockers:** None currently. PB1-T04 hit two consecutive Ruff E501 line-length
failures; work was stopped, the owner authorized correcting the SQL string, and
lint plus the full T04 suite subsequently passed. The owner approved the earlier
data-model, security and public API contract in [DR-006](../adr/DR-006.md).
PostgreSQL 18.6 is running locally in a disposable,
Unix-socket-only test cluster. Docker is not installed in the sandbox and is not
required by PB1. The initial mypy run failed because the locally built Python
lacked `_sqlite3`; the runtime was rebuilt with SQLite support and the same check
then passed. The downloaded test PostgreSQL package did not include `psql` or
`createdb`; the disposable database was created through psycopg instead.

**Decisions:** [DR-001](../adr/DR-001.md), [DR-002](../adr/DR-002.md),
[DR-003](../adr/DR-003.md), [DR-004](../adr/DR-004.md),
[DR-005](../adr/DR-005.md), [DR-006 — owner-approved](../adr/DR-006.md).

**CI scope:** PB1 lint/type checks, unit/integration/security tests, migration
round trips, dependency and secret checks apply as their tasks are implemented.
Governance coverage, import boundaries, registry, governance OpenAPI, compiler,
privilege and corpus gates have not been implemented and cannot pass until their
respective later phases. PB4 frontend and Compose checks are likewise pending.

**Next phase:** PB2 remains blocked until PB1 is complete and merged into `main`.
