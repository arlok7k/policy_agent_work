# Implementation progress

Current phase: **PB1 — backend skeleton, database core, authentication**

| Task | Status | Notes |
|---|---|---|
| PB1-T01 | Done | `make lint test typecheck`: 2 tests passed; scans and pre-commit passed |
| PB1-T02 | Done | 10 configuration/startup tests; settings and secret-file failures are closed |
| PB1-T03 | Done | PostgreSQL 18.6 session/transaction tests and Alembic up/down passed |
| PB1-T04 | Done | Revisions 001–003, audit trigger/privileges, real up/down; 27 tests passed |
| PB1-T05 | Done | Cookie authentication, CSRF and step-up; `make check` passed 52 tests |
| PB1-T06 | Done | Per-request current user and generic deny-by-default role guard; 62 tests passed |
| PB1-T07 | Done | Admin user APIs, race-safe role rechecks and revocation; 88 tests passed |
| PB1-T08 | In progress | Admin API-key lifecycle and service identity |
| PB1-T09 | Pending | Problem responses, correlation and JSON logging |
| PB1-T10 | Pending | Health endpoint |
| PB1-T11 | Pending | Environment-protected development seed |

**Blockers:** None currently. The owner approved option A in
[DR-009](../adr/DR-009.md), covering the user/API-key wire contracts, key
transport and administrative recovery protections. PB1-T06 passed
`make check PYTHON=.venv/bin/python` (62 tests, Ruff and mypy) and pre-commit.
PB1-T07 passed the same full check with 88 tests. An initial malformed-Unicode
security test failed in the HTTP test client's encoder before reaching the app;
the fixture's throwaway password/hash appeared in the default failure output.
The test was corrected and passed, and [DR-010](../adr/DR-010.md) records the
redacted failure-output policy and its regression test. The T07 audit reported
no known vulnerabilities or secret findings across 82 tracked files; all
pre-commit hooks passed.

**Resolved:** The original repository contained a root `README.md`
as well as the two reference files; the README was a single project-name heading.
PB1-T01 added the required reference links and PB1-T01–T04 were committed before
clarifying the initial-tree exception. Initial PB1-T05 code and tests were also
written. The owner subsequently approved treating that README as permitted
boilerplate, keeping the links and continuing PB1 on the current branch. The
T05 verification after review passed `make check PYTHON=.venv/bin/python` (52
tests, Ruff and mypy); this does not establish PB1 completion. T05's first
additional lint run reported two S105 false positives on numeric password-length
settings; the test was revised and the subsequent lint run passed. `make audit`
found no known vulnerabilities or secrets (67 tracked files). Pre-commit initially
failed because its system hooks selected `/usr/bin/python` instead of the virtual
environment; rerunning with `.venv/bin` on `PATH` passed all three hooks.

PB1-T04 previously hit two consecutive Ruff E501 line-length failures; the owner
authorized correcting the SQL string, and lint plus the full T04 suite passed.
The owner approved the earlier data-model, security and public API contract in
[DR-006](../adr/DR-006.md). PostgreSQL 18.6 runs locally in a disposable,
Unix-socket-only test cluster. Docker is not installed and is not required by
PB1. The initial mypy run failed because locally built Python lacked `_sqlite3`;
the runtime was rebuilt with SQLite support and the same check then passed. The
downloaded test PostgreSQL package did not include `psql` or `createdb`; the
disposable database was created through psycopg instead.

**Decisions:** [DR-001](../adr/DR-001.md), [DR-002](../adr/DR-002.md),
[DR-003](../adr/DR-003.md), [DR-004](../adr/DR-004.md),
[DR-005](../adr/DR-005.md), [DR-006 — owner-approved](../adr/DR-006.md),
[DR-007 — authentication implementation details](../adr/DR-007.md),
[DR-008 — legacy role dependency](../adr/DR-008.md). DR-007 and DR-008 implement
the owner-approved DR-006 contract and have not received separate owner approval.
[DR-009 — user/API-key details](../adr/DR-009.md) is owner-approved;
[DR-010 — redacted test output](../adr/DR-010.md) is an implementation decision.

**CI scope:** PB1 lint/type checks, unit/integration/security tests, migration
round trips, dependency and secret checks apply as their tasks are implemented.
Governance coverage, import boundaries, registry, governance OpenAPI, compiler,
privilege and corpus gates have not been implemented and cannot pass until their
respective later phases. PB4 frontend and Compose checks are likewise pending.

**Next phase:** PB2 remains blocked until PB1 is complete and merged into `main`.
