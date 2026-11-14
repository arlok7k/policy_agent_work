# Implementation progress

Current phase: **PB2 — alerts, incidents, evidence, threat-intel and AI adapters**

PB1 was merged into `main` at `fa8b726`. Before PB2 changes, the unchanged
baseline passed `make check PYTHON=.venv/bin/python` in a network-isolated
namespace: 131 tests, Ruff and mypy. `make audit` and pre-commit also passed.

## PB2 task list

| Task | Status | Notes |
|---|---|---|
| PB2-T01 | Done | Migrations 004–005, constraints, runtime grants and stepwise up/down on disposable PostgreSQL; [DR-015](../adr/DR-015.md). The affected suite passed 17 tests; full isolated `make check` passed 136 tests. |
| PB2-T02 | Done | File-only HMAC secret, streaming cap, schema validation, Redis replay reservations and Celery publication; [DR-016](../adr/DR-016.md). The affected suite passed 22 tests; full isolated `make check` passed 158 tests. |
| PB2-T03 | Done | JSON-only Celery worker, mandatory initiator headers, canonical normalization and atomic fingerprint deduplication; [DR-016](../adr/DR-016.md). Affected suite: 23 passed, including a real Redis worker; full isolated `make check`: 166 passed. |
| PB2-T04 | Done | Role-protected alert list/detail/summary, filters and stable keyset cursors; [DR-017](../adr/DR-017.md). The affected isolated suite passed 26 tests. |
| PB2-T05 | Done | Deterministic mock-only IP verdicts, deadline degradation, DB-authoritative Redis cache, bounded bulk and stats; [DR-018](../adr/DR-018.md). The affected isolated suite passed 31 tests. |
| PB2-T06 | Done | Three deterministic `mock=true` AI routes with minimized alert context and no governance data; [DR-019](../adr/DR-019.md). The affected isolated suite passed 18 tests. |
| PB2-T07 | Done | Bounded incident creation, scoped evidence and transactional investigation/audit with both mock adapters; [DR-020](../adr/DR-020.md). The affected isolated suite passed 46 tests. |
| PB2-T08 | Done | Every host operation is inventoried and exercised across active roles, service, inactive, unlisted and anonymous principals, including CSRF and fail-closed policy checks; [DR-021](../adr/DR-021.md). The affected isolated suite passed 42 tests. |
| PB2-T09 | Done locally | Reproducible OpenAPI 3.1 export, response/status schema contracts and network-isolated CI; [DR-023](../adr/DR-023.md). Full isolated `make check`: 235 passed; final-head CI is tracked in the PR checks. |

PB2-T02's first lint run found an unused import, and its first mypy run found a
third-party Redis type-parameter mismatch; both were corrected before the
successful checks. The dependency audit reported no known vulnerabilities and
the secret scan found no findings in 125 tracked files; pre-commit passed.
PB2-T03's first mypy run identified missing generic type arguments for the
Celery stubs; these were added, and the subsequent checks passed. The initial
focused run emitted a Celery startup-retry deprecation warning; explicit startup
configuration removed it, and the full run above passed without warnings.
PB2-T04's first lint run found four overlong SQL literals in test fixtures; the
strings were split without changing SQL, and the repeat lint and tests passed.
PB2-T05's first lint run found one overlong test SQL literal; the first mypy
run also flagged two unvalidated database-to-schema argument types. The SQL was
split, the DB row is now validated as data, and the repeat checks passed.
PB2-T06's first lint run requested Python's modern generic-function syntax;
the helper was updated and the repeat lint and type checks passed.
PB2-T07 had two consecutive Ruff E501 failures on three unchanged long SQL
literals; the owner selected **“Fix and continue”** when asked whether to split
those literals and continue. They were split without changing SQL or tests, and
subsequent Ruff, mypy and the affected network-isolated suite passed.
PB2-T08's first expanded suite had one test-fixture failure: pytest 9.2's
attribute patch restoration removed a dynamically stored Starlette `State`
attribute after the first loop iteration. Patching its backing mapping preserves
the original entry; the repeat run passed all 42 tests without reducing checks.
PB2-PB4-FU01's first Ruff check found one unsorted import; it was fixed and the
repeat checks passed. The affected isolated suite passed 65 tests, including a
real Beat dispatch, worker initiator enforcement, database-clock bounded cleanup,
active throttles and concurrent login/cleanup races.
PB2-T09's first Ruff check found an extra blank import separator; the first CI
runner check flagged a partial `make` path and an exec-process warning. The
imports were formatted and `make` is now resolved before a fixed-argument,
no-shell exec. Subsequent lint and mypy passed. The final local CI-equivalent
command, `CI_DISPOSABLE_SERVICES=1 .venv/bin/python scripts/ci_isolated_checks.py`
with the disposable local service ports and database explicitly supplied, verified
no IPv4/IPv6 loopback or external route and passed Ruff, formatting, mypy,
OpenAPI drift and **235 tests**. `make audit PYTHON=.venv/bin/python` found no
known vulnerabilities, unrecognized licenses or secrets across 178 tracked
files; all pre-commit hooks passed. LGPL legal review remains an open risk.
GitHub final-head CI is tracked separately in the PR checks and is not implied
by this local run.

### PB2 acceptance evidence

| Criterion | Evidence and status |
|---|---|
| AC-B2.1 | PB2 host operations are in `openapi.host.json`; real success/error responses and the complete legacy matrix are schema-checked by `backend/tests/contract/`. Local full suite passed; see PR checks for final-head CI. PB3 response routes are intentionally not claimed. |
| AC-B2.2 | `backend/tests/integration/test_webhook.py` verifies missing/bad HMAC produces a generic rejection with no DB, broker or Redis effects; replay, malformed and oversized cases are also exercised. |
| AC-B2.3 | `test_alert_storage.py` and the real webhook-to-worker integration test verify concurrent/queued fingerprint deduplication. |
| AC-B2.4 | The application registers only mock providers. The CI-equivalent runner verified absent IP routes before all application tests, using only fixed Unix bridges to disposable PostgreSQL and Redis. See PR checks for GitHub CI. |

Owner review/merge, PB4 baseline approval, and future-phase governance gates are
pending; none is represented as passed by these local results.

## PB1 completed tasks

| Task | Status | Notes |
|---|---|---|
| PB1-T01 | Done | Scaffold and empty future-package directories; initial checks passed |
| PB1-T02 | Done | 10 configuration/startup tests; settings and secret-file failures are closed |
| PB1-T03 | Done | PostgreSQL 18.6 session/transaction tests and Alembic up/down passed |
| PB1-T04 | Done | Revisions 001–003, audit trigger/privileges, real up/down; 27 tests passed |
| PB1-T05 | Done | Cookie authentication, CSRF and step-up; `make check` passed 52 tests |
| PB1-T06 | Done | Per-request current user and generic deny-by-default role guard; 62 tests passed |
| PB1-T07 | Done | Admin user APIs, race-safe role rechecks and revocation; 88 tests passed |
| PB1-T08 | Done | Owned API keys and service-principal auth; 100 tests passed |
| PB1-T09 | Done | Typed errors, problem responses, correlation and redacted JSON logs; 114 tests passed |
| PB1-T10 | Done | Public database readiness with real healthy/unreachable checks; 116 tests passed |
| PB1-T11 | Done | Atomic development-only seed and safe run instructions; 128 tests passed |

## PB1 review follow-ups

| Task | Status | Notes |
|---|---|---|
| PB1-R01 | Done locally | Normal short pytest diagnostics and captured output restored; test credentials wrapped; regression retained. Full suite: 131 passed; see the PR for CI status. |
| PB1-R02 | Done | DR-002, DR-006, DR-009 and DR-013 approval is marked to be confirmed because exact owner messages are unavailable in the current context. |
| PB1-R03 | Done | The four requested PB2/PB4/P1 follow-ups are tracked below; the scheduler follow-up is now completed in PB2. |

PB1-R01's focused output regression passed (4 tests). The first audit flagged two
nonsecret expected-value literals in its failure probes as secret-keyword false
positives; the assertions now use named expected values. The regression and a
repeat `make audit PYTHON=.venv/bin/python` passed, with no known vulnerabilities
or secret findings across 112 tracked files. Pre-commit passed.

**Review status:** Owner approval of DR-002, DR-006, DR-009 and DR-013 is
**to be confirmed**: the available session summary records option A selections,
but does not preserve the exact owner messages. The spec's literal DoD-common
requires all G-A–G-M gates in every phase, but the roadmap introduces several
only in P1/P8 and the owner restricted this request to PB1. Under the implemented
[DR-002](../adr/DR-002.md) interpretation, future-scope gates remain pending,
not passed, and mandatory in their roadmap phases. PB1's earlier GitHub Actions
workflow passed on commit `91c552b` (run 43372484803); later governance gates
did not run. The updated branch and PR must pass their own CI runs.

**Implemented:** [DR-013](../adr/DR-013.md) option A exposes minimal public
readiness; the owner-approval evidence is to be confirmed.

**Implemented:** [DR-009](../adr/DR-009.md) option A covers the user/API-key
wire contracts, key transport and administrative recovery protections; the
owner-approval evidence is to be confirmed. PB1-T06 passed
`make check PYTHON=.venv/bin/python` (62 tests, Ruff and mypy) and pre-commit.
PB1-T07 passed the same full check with 88 tests. An initial malformed-Unicode
security test failed in the HTTP test client's encoder before reaching the app;
the fixture's throwaway password/hash appeared in the default failure output.
The test was corrected and passed. Following PB1 review,
[DR-010](../adr/DR-010.md) supersedes the earlier suppressed-output policy with
normal short tracebacks, captured output and source-level test-value redaction.
The T07 audit reported
no known vulnerabilities or secret findings across 82 tracked files; all
pre-commit hooks passed. PB1-T08 passed `make check PYTHON=.venv/bin/python`
(100 tests, Ruff and mypy), including owned-key IDOR, revocation, service-role
isolation and mid-request demotion tests. The T08 audit found no known
vulnerabilities or secret findings across 88 tracked files; pre-commit passed.
PB1-T09 passed `make check PYTHON=.venv/bin/python` (114 tests, Ruff and mypy),
including correlated audit records and credential-safe success/failure logs.
The T09 audit found no known vulnerabilities or secrets across 95 tracked files;
pre-commit passed. PB1-T10's two focused health tests and the full
`make check PYTHON=.venv/bin/python` suite passed (116 tests, Ruff and mypy).
The T10 audit found no known vulnerabilities or secrets across 98 tracked files;
pre-commit passed. Final PB1 verification passed
`make check PYTHON=.venv/bin/python` (128 tests, Ruff, mypy including scripts).
The disposable database was separately preflighted, upgraded to revision 003,
and downgraded to base; only empty Alembic metadata remained. Final review also
added unit CSRF coverage, a distributed per-account throttle test, and bounded
writes for requests from an already-blocked source. The final local `make audit`
found no known vulnerabilities or secrets across 102 tracked files; all
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
The implemented data-model, security and public API contract is in
[DR-006](../adr/DR-006.md); its owner-approval evidence is to be confirmed.
PostgreSQL 18.6 runs locally in a disposable, Unix-socket-only test cluster.
Docker is not installed and is not required by
PB1. The initial mypy run failed because locally built Python lacked `_sqlite3`;
the runtime was rebuilt with SQLite support and the same check then passed. The
downloaded test PostgreSQL package did not include `psql` or `createdb`; the
disposable database was created through psycopg instead.

**Decisions:** [DR-001](../adr/DR-001.md), [DR-002](../adr/DR-002.md),
[DR-003](../adr/DR-003.md), [DR-004](../adr/DR-004.md),
[DR-005](../adr/DR-005.md), [DR-006](../adr/DR-006.md),
[DR-007 — authentication implementation details](../adr/DR-007.md),
[DR-008 — legacy role dependency](../adr/DR-008.md),
[DR-009 — user/API-key details](../adr/DR-009.md),
[DR-010 — test credential redaction](../adr/DR-010.md),
[DR-011 — key representation](../adr/DR-011.md),
[DR-012 — errors and logging](../adr/DR-012.md),
[DR-013 — public health access](../adr/DR-013.md), and
[DR-014 — development seed](../adr/DR-014.md). Owner approval for DR-002,
DR-006, DR-009 and DR-013 is to be confirmed; DR-007, DR-008, DR-010, DR-011,
DR-012 and DR-014 are implementation decisions.

**CI scope:** PB1 lint/type checks, unit/integration/security tests, migration
round trips, dependency and secret checks are implemented. The prior push run
passed on `91c552b`; the PR workflow must also pass before the PR is ready, and
its actual result will be recorded on the PR.
Governance coverage, import boundaries, registry, governance OpenAPI, compiler,
privilege and corpus gates have not been implemented and cannot pass until their
respective later phases. The spec's literal DoD-common calls for all G-A–G-M
at every phase, although the roadmap introduces several only in P1/P8; they are
not claimed as passing here (see DR-002). PB4 frontend/Compose checks are pending.

**Open risks:** Login-throttle cleanup requires Beat to run and all API/worker
replicas to share the same login window; source-IP quotas require a trusted
proxy boundary and upstream volumetric controls. Redis loss can lose webhook
replay reservations, and HTTP 202 means queued rather than persisted. Mock
intelligence/AI output is synthetic and must not be mistaken for real provider
results. Legal review of the LGPL-3.0-only psycopg packages is still needed. The implemented
public health endpoint reveals database readiness to callers who can reach it;
its approval evidence is to be confirmed.

**CI evidence limitation:** GitHub reported the push workflow's successful
conclusion, but the sandbox could not fetch its log archive from GitHub's log
host. The CLI error displayed a temporary signed download URL; it is not copied
here. An optional actions-permissions API lookup also returned HTTP 403; other
repository, push and workflow-status operations succeeded.

## Deferred phase follow-ups

These are tracked, not implemented, and do not authorize starting a later phase.
Security-boundary choices must follow the specification's owner-decision process.

| Task | Target | Status | Required outcome |
|---|---|---|---|
| PB4-FU01 | PB4 | Not started | Implement a trusted Nginx/proxy boundary so rate limits and audit use the real client IP. Nginx must strip or overwrite externally supplied `X-Forwarded-For` at ingress; the backend may trust forwarding information only from explicitly configured proxy hops. Test legitimate forwarding and spoofed headers both directly and through Nginx. |
| PB4-FU02 | PB4 | Not started | Define and test a safe local HTTP development cookie flow without weakening production: production session cookies must retain `Secure` and existing protections, and an insecure development setting must not silently apply in production. Document the development boundary and test both environments. |
| PB2-PB4-FU01 | PB2/PB4 | Done | Celery Beat schedules bounded, database-time cleanup with a service initiator; active limits and both login/cleanup lock orders are tested. See [DR-022](../adr/DR-022.md). The affected isolated suite passed 65 tests. |
| P1-FU01 | P1 | Not started | Test the Cedar binding on the pinned CPython 3.15 runtime. If it is unsupported, stop and report options and consequences to the owner before changing Python or binding versions. |

**Next phase:** Finish PB2, open its PR and wait for the owner's review and
merge. Do not start PB3 in this request.
