# PHASE REPORT — PB3: HPB response domain

**Tasks completed:** PB2-FIX01; PB3-T01–T10.

**Files created / modified:** See the complete path inventory and reasons below.

**Tests run:**

- Before PB3, the unchanged PB2 baseline passed the isolated runner: 235 tests,
  Ruff, formatting, mypy and OpenAPI drift checks.
- The PB2-FIX01 affected isolated suite passed 48 tests. The individual PB3
  tasks also ran their affected suites; counts and initial failures are recorded
  in [PROGRESS.md](PROGRESS.md).
- The full disposable-service command
  `CI_DISPOSABLE_SERVICES=1 .venv/bin/python scripts/ci_isolated_checks.py --database-user pb3_test_owner --database smart_soc_pb3_test --postgres-port 35432 --broker-port 36379 --cache-port 36380`
  verified no loopback or external IPv4/IPv6 routes, then passed Ruff, formatting,
  mypy, OpenAPI drift and **354 tests**. The initial full run had 353 passes and
  one fixture failure caused by an invalid random idempotency-key prefix; that
  fixture was corrected without changing the API or the assertions, and the
  repeated full run passed.
- `make audit PYTHON=.venv/bin/python` found no known vulnerabilities or
  unknown licenses; its secret scan found no findings across 228 tracked files.
  The LGPL-3.0-only dependency review is still open. Pre-commit's Ruff, format
  and mypy hooks passed. Final-head GitHub results are tracked separately on the
  PR and are not inferred from these local results.

**Acceptance criteria:**

| Criterion | Evidence |
|---|---|
| AC-B3.1 | `test_approval_gate.py`, `test_response_security.py`, `test_response_characterization.py`, and DB-trigger tests enforce distinct senior/admin approval, reject self-approval, serialize competing decisions, and revalidate the actual worker path. |
| AC-B3.2 | `test_response_security.py`, `test_response_api.py`, `test_response_safeguards.py`, and `test_simulated_connectors.py` reject Agent 000, 10.0.0.5, 127.0.0.1 and shell injection at request and execution; changed rules are tested after approval. |
| AC-B3.3 | `test_response_ttl.py` freezes the database-clock accessor at the before/equal/after boundary, covers both L2 modes, and dispatches the TTL task to a real worker; unsafe reversals remain executed and retry. |
| AC-B3.4 | `test_kill_switch.py` tests audit, same-value reaffirmation and a queued task in an already-running worker, including a controlled ≤1.5-second observation after engagement; manual execution remains available and automation resumes. This is a target observation, not an SLA under contention. |
| AC-B3.5 | `test_simulated_connectors.py` intercepts socket connect/connect_ex/sendto, connection helpers and DNS for both connectors; the full isolated suite additionally ran without IP routing. |

**Deviations / DRs:** [DR-024](../adr/DR-024.md) documents the requested PB2
webhook follow-up. [DR-025](../adr/DR-025.md)–[DR-033](../adr/DR-033.md)
record PB3's persistence, catalog, safeguards, approval, connectors, execution,
TTL, Kill Switch, API and recovery decisions. DR-002's phase-specific
interpretation of future governance gates remains in effect; later-phase gates
are pending, not passed. The owner selected preservation of HTTP 400 for an
overlong decision reason; the length and no-mutation checks remain in force.

**Open risks:**

- PB4 baseline approval is pending; the owner must review the legacy matrix and
  open semantics before the host baseline is frozen. Approval evidence for
  DR-002, DR-006, DR-009 and DR-013 remains to be confirmed.
- Earlier *unmerged development* versions of migrations 006–008 can share the
  final revision number without the final idempotency columns. Only the upgrade
  from released PB2 revision 005 is supported and tested. Never rebuild a
  persistent database; a previously migrated development database requires a
  separate reviewed migration plan before use with final PB3 code.
- Pending and approved human decisions have no PB3 expiry. The `expired` state
  is reserved; indefinite approvals are a PB4 review item.
- Recovery, propagation and TTL timing depend on a functioning database, trusted
  broker, Beat, workers and consistent replica settings. A committed response
  means durable intent, not confirmed publication or execution. Contention or an
  in-flight transaction can delay the approximately one-second switch target.
- A prohibited TTL reverse remains executed and retries when safe; a refused
  manual rollback requires a fresh human request. Connector output is simulated,
  and there is no real containment or Wazuh network call.
- Legal review of the LGPL-3.0-only psycopg dependencies remains outstanding.

**Gate status:** PB3-specific AC-B3.1–B3.5 and the local isolated checks pass;
PB3 has no phase human gate. Final-head CI and PR readiness are tracked on the
PR. PB4/P0 approvals, frontend/Compose work, and later governance gates are
pending and are not claimed as passed.

**Next:** After the owner reviews and merges the PB3 PR, begin PB4 only on
explicit authorization; do not start it as part of this PB3 request.

## File inventory

Paths are compared with the PB2 base. New files are grouped by their exact
paths; each pre-existing modified file includes the reason for its change.

### Created

- `backend/app/connectors/__init__.py`, `backend/app/connectors/base.py`,
  `backend/app/connectors/internal.py`, `backend/app/connectors/registry.py`,
  `backend/app/connectors/simulated_wazuh.py` — simulation-only connector layer.
- `backend/app/core/pb3_config.py` — bounded recovery and TTL settings.
- `backend/app/response/__init__.py`, `backend/app/response/catalog.py`,
  `backend/app/response/execution.py`, `backend/app/response/gate.py`,
  `backend/app/response/manual_rollback.py`, `backend/app/response/models.py`,
  `backend/app/response/router.py`, `backend/app/response/rules.py`,
  `backend/app/response/safeguards.py`, `backend/app/response/schemas.py`,
  `backend/app/response/service.py`, `backend/app/response/switch.py`,
  `backend/app/response/ttl.py` — the response domain and its safety controls.
- `backend/migrations/versions/006_response_actions.py`,
  `backend/migrations/versions/007_response_audit.py`,
  `backend/migrations/versions/008_response_safety.py` — PB3 persistence.
- `backend/tests/contract/test_response_characterization.py`,
  `backend/tests/integration/test_approval_gate.py`,
  `backend/tests/integration/test_connector_recording.py`,
  `backend/tests/integration/test_kill_switch.py`,
  `backend/tests/integration/test_pb3_migrations.py`,
  `backend/tests/integration/test_response_api.py`,
  `backend/tests/integration/test_response_catalog_api.py`,
  `backend/tests/integration/test_response_execution.py`,
  `backend/tests/integration/test_response_recovery_bound.py`,
  `backend/tests/integration/test_response_security.py`,
  `backend/tests/integration/test_response_ttl.py`,
  `backend/tests/integration/test_safety_snapshot.py`,
  `backend/tests/unit/test_response_catalog.py`,
  `backend/tests/unit/test_response_gate.py`,
  `backend/tests/unit/test_response_safeguards.py`,
  `backend/tests/unit/test_response_schedule.py`,
  `backend/tests/unit/test_simulated_connectors.py` — PB3 regression suites.
- `docs/adr/DR-024.md`, `docs/adr/DR-025.md`, `docs/adr/DR-026.md`,
  `docs/adr/DR-027.md`, `docs/adr/DR-028.md`, `docs/adr/DR-029.md`,
  `docs/adr/DR-030.md`, `docs/adr/DR-031.md`, `docs/adr/DR-032.md`,
  `docs/adr/DR-033.md`, `docs/governance/PB3_PHASE_REPORT.md` — decisions and
  this report.

### Pre-existing files modified

- `.env.example` — document webhook retry and response sweep/TTL settings.
- `backend/app/alerts/webhook.py` — return a retry hint on dependency failures.
- `backend/app/auth/legacy_roles.json` — register legacy response operations.
- `backend/app/core/errors.py`, `backend/app/core/exceptions.py` — safely carry
  the explicit webhook 503 retry hint.
- `backend/app/core/openapi.py` — publish retry, response-route and error contracts.
- `backend/app/core/pb2_config.py` — validate the configurable webhook retry hint.
- `backend/app/jobs/celery_app.py` — register attributed response tasks and Beat schedules.
- `backend/app/jobs/tasks.py` — execute and reconcile response actions and rollbacks.
- `backend/app/main.py` — wire PB3 configuration, router and Celery settings.
- `backend/tests/contract/test_legacy_matrix.py` — extend the independent route/role matrix.
- `backend/tests/contract/test_openapi_contract.py` — verify the webhook retry header.
- `backend/tests/contract/test_policy_fail_closed.py` — cover response role failures.
- `backend/tests/integration/test_host_migrations.py` — extend the head schema inventory.
- `backend/tests/integration/test_pb2_migrations.py` — expect PB3 after upgrading to head.
- `backend/tests/integration/test_throttle_cleanup.py` — include PB3 in Beat inventory.
- `backend/tests/integration/test_webhook.py` — exercise retry hints and dependency failures.
- `backend/tests/unit/test_errors.py` — verify safe propagation of retry headers.
- `backend/tests/unit/test_pb2_config.py` — validate retry-hint configuration.
- `backend/tests/unit/test_throttle_schedule.py` — update the exact Beat schedule inventory.
- `docs/governance/PROGRESS.md` — record task status, results and decisions.
- `docs/governance/config.md` — document new settings and operating limitations.
- `openapi.host.json` — regenerate the host API and retry-header contract.
