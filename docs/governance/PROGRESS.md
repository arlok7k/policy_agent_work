# Implementation progress

Current phase: **PB1 — backend skeleton, database core, authentication**

| Task | Status | Notes |
|---|---|---|
| PB1-T01 | Done | `make lint test typecheck`: 2 tests passed; scans and pre-commit passed |
| PB1-T02 | In progress | Typed env/secret-file settings and startup validation |
| PB1-T03 | Pending | PostgreSQL session layer and Alembic |
| PB1-T04 | Pending | Revisions 001–003 and append-only activities |
| PB1-T05 | Pending | Login/logout/me/reauth, rate limiting, cookies, CSRF |
| PB1-T06 | Pending | Current principal and legacy role guard |
| PB1-T07 | Pending | Admin users and session revocation |
| PB1-T08 | Pending | Admin API-key lifecycle and service identity |
| PB1-T09 | Pending | Problem responses, correlation and JSON logging |
| PB1-T10 | Pending | Health endpoint |
| PB1-T11 | Pending | Environment-protected development seed |

**Blockers:** None currently; required PostgreSQL tests still need execution.
Docker is not installed in the sandbox and is not required by PB1. The initial
mypy run failed because the locally built Python lacked `_sqlite3`; the runtime
was rebuilt with SQLite support and the same check then passed.

**Decisions:** [DR-001](../adr/DR-001.md), [DR-002](../adr/DR-002.md).

**CI scope:** PB1 lint/type checks, unit/integration/security tests, migration
round trips, dependency and secret checks apply as their tasks are implemented.
Governance coverage, import boundaries, registry, governance OpenAPI, compiler,
privilege and corpus gates have not been implemented and cannot pass until their
respective later phases. PB4 frontend and Compose checks are likewise pending.

**Next phase:** PB2 remains blocked until PB1 is complete and merged into `main`.
