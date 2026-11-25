# PHASE REPORT — PB4: HPB frontend shell, infrastructure and end-to-end smoke

**Gate status: NOT PASSED.** The PB4 owner must run and review the baseline,
legacy authorization and open decisions before explicitly approving it; P0 is
not authorized. Real CI for the selected host-isolation change passed; the PR's
final-head checks must also pass separately.

**Tasks implemented:** PB4-T01–T09 and PB4-FU01–FU07. FU01–FU06 cover proxy
trust, development cookies, static-address reservation, worker startup, focus
restoration and host isolation. FU07 records the migration-commit deviation.
Implementation alone is not phase completion or baseline approval.

**Files created / modified:** The complete inventory, including the reason for
each changed pre-existing file, is below. This report compares against the PB3
merge commit `b9d812e4306bf47841d4ee7c9b0a21f95028c98d`.

**Tests run:**

- The full local backend gate used disposable PostgreSQL and two disposable
  Redis instances through Unix-socket bridges:
  `CI_DISPOSABLE_SERVICES=1 .cache/pb4-tools/venv315/bin/python scripts/ci_isolated_checks.py --database-user hpb_owner --database soc_compose_test --postgres-port 55432 --broker-port 56379 --cache-port 56380`.
  The runner verified that the test namespace had no loopback or external
  IPv4/IPv6 route, and passed Ruff, format, mypy, OpenAPI drift and **413 tests**
  including the backend, contract and disposable-migration suites.
- The focused isolation/Compose-IPAM/guide command
  `.cache/pb4-tools/venv315/bin/python -m pytest -q backend/tests/unit/test_pb4_host_isolation.py backend/tests/unit/test_pb4_infra.py backend/tests/unit/test_pb4_compose_ipam.py backend/tests/unit/test_pb4_operator_guide.py`
  passed **37 tests**. Ruff, formatting and mypy passed for the new checker;
  the host script parsed under Python 3.10 grammar and compiled on Python 3.11.
  With no local Docker, its preflight correctly returned nonzero rather than
  claiming verification. A deliberately failing first config test exposed the
  absent isolation option. An initial formatting check exposed an incompatible
  Python-3.15-only exception syntax, and a distinct lint check found a deprecated
  timeout alias in a test; both were corrected and the repeated checks passed.
- `PATH="$PWD/.cache/pb4-tools/venv315/bin:$PATH" .cache/pb4-tools/venv315/bin/pre-commit run --all-files`
  passed Ruff lint, Ruff format and mypy. The staged secret scan found no
  findings in 328 tracked files. Relative links in the changed guide/decision
  documents resolved, and all five guide shell blocks passed `bash -n`.
- `python -m pip_audit --disable-pip --require-hashes -r requirements.lock`
  reported no known vulnerabilities; `python -m piplicenses --with-system
  --fail-on UNKNOWN` passed the unknown-license check. This does not resolve the
  separate LGPL legal review described below.
- Frontend lint, type-check, **23 Vitest tests**, production build and npm audit
  passed locally (Node 22.22.3); the build retained a non-failing chunk-size
  warning. Earlier full CI used the pinned Node 26.13.1. The exact signed
  webhook example also returned HTTP 202 against a disposable local API and
  was normalized by the separate worker; this local run was not Compose.
- The unchanged real Compose browser/security smoke and all three CI jobs
  passed in [run 45632988120](https://github.com/arlok7k/policy_agent_work/actions/runs/45632988120)
  on `faaa63b`, and [run 45635828310](https://github.com/arlok7k/policy_agent_work/actions/runs/45635828310)
  passed on `e2e0045`. Both predate the isolated gateway and neither establishes
  Docker-host isolation. After the change, real
  [run 45664281012](https://github.com/arlok7k/policy_agent_work/actions/runs/45664281012)
  passed all three jobs on `2701953`, including compatible-engine preflight,
  isolated startup, Nginx configuration/health, host-negative and internal-positive
  controls, and the unchanged edge/browser smoke. Final-head PR checks are
  authoritative and are not inferred from this earlier run.
- The earlier Compose startup failure, IPAM correction, worker and dialog-focus
  smoke failures and fixes are recorded with their evidence in [PROGRESS.md](PROGRESS.md).
  No assertion or security safeguard was disabled to obtain a pass.

**Acceptance criteria:**

| Criterion | Evidence / status |
|---|---|
| AC-B4.1 — clean Compose startup and health | The isolated-gateway stack started from the clean CI checkout and passed health and `nginx -t` in run 45664281012. The development bootstrap is explicit and refuses to overwrite secret files. Final-head CI still applies. |
| AC-B4.2 — Playwright smoke | Complete real signed webhook → investigate → L3 request → different eligible approver → simulated executed-command → Kill Switch, including negative/security cases, passed unchanged on the isolated network in run 45664281012. Final-head CI still applies. |
| AC-B4.3 — browser API-only and data-network isolation | The smoke asserts same-origin data requests use `/api/`, checks no other origin/WebSocket and probes each actual PostgreSQL/Redis IP from an edge-only client. Run 45664281012 also passed the IPv4-only isolated bridge, host-negative and internal-positive controls. Final-head CI and the deployment-specific host checks still apply. |
| AC-B4.4 — routes and unauthenticated redirect | The unchanged real browser smoke visited the route/placeholder headings, checked redirects and exercised role-restricted paths, RTL, slow responses, pagination and session expiry in run 45664281012. Final-head CI still applies. |
| AC-B4.5 — CI and contracts | Run 45664281012 passed backend (including PB2/PB3 contract and migration checks), frontend and Compose jobs. The PR's final-head CI must pass separately. |

**Deviations / decision records:**

- [DR-034](../adr/DR-034.md)–[DR-038](../adr/DR-038.md): pinned frontend,
  shell, owner-authorized host read APIs, presentation settings and UI primitives.
- [DR-039](../adr/DR-039.md)–[DR-046](../adr/DR-046.md): exact proxy trust,
  opt-in development cookies, deployment/secrets, Nginx, CI, IPAM, smoke and
  the owner-selected PB4-only worker bootstrap. The adapter does not change PB3
  response semantics.
- [DR-047](../adr/DR-047.md): migration `009_host_settings` was committed with
  PB4-T03 implementation in `4debaf5`, not in its own commit as R-17 requires.
  This is a recorded process deviation for owner review, not a waiver. Pushed
  history was not rewritten and the database was not rebuilt to disguise it.
- [DR-048](../adr/DR-048.md): the owner selected isolated-gateway host
  protection rather than silently assuming the Docker host trusted. Real runtime
  checks passed in run 45664281012; final-head CI and separate owner baseline
  approval remain required.
- Approval evidence for [DR-002](../adr/DR-002.md), [DR-006](../adr/DR-006.md),
  [DR-009](../adr/DR-009.md) and [DR-013](../adr/DR-013.md) remains to be
  confirmed; do not infer it from previous summaries or green tests.

**Open risks and limitations:**

- The isolated gateway requires stable native Linux Docker Engine 28+ and a
  local socket to that same host. The checks measure their invoking host process,
  not all host policies, and must be rerun after network/daemon/deployment
  changes. Root, Docker administrators and compromised internal services can
  bypass the boundary; Redis is unauthenticated on the internal network.
- TLS is an inactive, operator-provisioned template. A local mock-upstream test
  exercised TLS/HSTS, but the official-image Compose TLS setup has not been
  independently verified. The real browser smoke uses explicit development-only
  HTTP cookies; production Secure `__Host-` behavior is covered by backend tests.
  Spoofed-header attribution is tested at the application boundary and with a
  local mock Nginx, not independently asserted end-to-end through real Nginx.
- `psycopg` and `psycopg-binary` 3.3.9 were identified as LGPL-3.0-only in the
  license inventory; legal suitability/review remains open even when the
  automated dependency and unknown-license checks pass.
- Threat-intelligence and AI providers are mocks; response connectors are
  simulated and cannot isolate a real host. Redis/broker data is ephemeral;
  HTTP 202 means queued, not durable ingestion. Production secrets, certificates,
  backups, monitoring and deployment hardening require operator work.
- Earlier unmerged development databases at PB3 migration 008 may lack final
  columns despite the same revision identifier; [DR-033](../adr/DR-033.md)
  requires a reviewed migration plan. Never rebuild retained data or use the
  destructive disposable-test cleanup on it. Pending approvals have no default
  expiration, and Kill Switch timing is not a contention-independent SLA.

**Gate status by exit condition:**

| Exit condition | Status |
|---|---|
| Real Compose/Playwright and host isolation | Passed on `2701953` in run 45664281012; deployment-specific checks remain necessary. |
| Final-head CI | Must pass on the PR head; inspect the PR checks. |
| Phase Report and disclosed decisions/deviations | Recorded here; R-17 and earlier approval evidence require human review. |
| Owner runs stack and reviews legacy authorization/DRs | Not yet evidenced. |
| Explicit PB4 baseline approval | Not given. Green tests do not grant it. |
| P0 authorization | Not given. Do not start P0. |

**Next:** After the owner runs the documented stack and reviews
[`legacy_roles.json`](../../backend/app/auth/legacy_roles.json), the open
response semantics and DRs, request explicit PB4 baseline approval. A separate
explicit go-ahead is needed before starting P0.

## File inventory

### Created

- `.dockerignore` — excludes secrets and build artifacts from image contexts.
- `backend/app/core/gunicorn_worker.py`, `backend/app/jobs/compose_worker.py` —
  preserve real peer attribution and register worker ORM metadata at startup.
- `backend/app/settings/__init__.py`, `backend/app/settings/router.py`,
  `backend/app/settings/schemas.py` — audited host-only presentation settings.
- `backend/migrations/versions/009_host_settings.py` — additive settings table.
- `backend/tests/integration/test_pb4_dev_cookies.py`,
  `backend/tests/integration/test_pb4_host_api.py`,
  `backend/tests/integration/test_pb4_provision.py`,
  `backend/tests/integration/test_pb4_proxy_attribution.py`,
  `backend/tests/integration/test_pb4_separate_worker.py` — cookie, API,
  runtime-identity, proxy and worker regressions.
- `backend/tests/unit/test_compose_log_redaction.py`,
  `backend/tests/unit/test_pb4_compose_ipam.py`,
  `backend/tests/unit/test_pb4_e2e_runner.py`,
  `backend/tests/unit/test_pb4_host_isolation.py`,
  `backend/tests/unit/test_pb4_infra.py`, `backend/tests/unit/test_pb4_nginx.py`,
  `backend/tests/unit/test_pb4_operator_guide.py`,
  `backend/tests/unit/test_pb4_worker_bootstrap.py`, `backend/uvicorn_worker.pyi`
  — infrastructure, diagnostics, host-network, guide and worker checks/types.
- `docs/adr/DR-034.md` through `docs/adr/DR-048.md`,
  `docs/governance/HPB_README.md`, `docs/governance/PB4_PHASE_REPORT.md` —
  decisions, operator guidance and this report.
- `frontend/e2e/host-smoke.spec.ts`, `frontend/e2e/redaction.ts`,
  `frontend/e2e/safe-reporter.ts`, `frontend/playwright.config.ts` — real,
  redacted browser smoke.
- `frontend/eslint.config.js`, `frontend/index.html`, `frontend/package.json`,
  `frontend/package-lock.json`, `frontend/postcss.config.js`,
  `frontend/tailwind.config.js`, `frontend/tsconfig.json`, `frontend/vite.config.ts`
  — pinned frontend build and test infrastructure.
- `frontend/src/api/client.test.ts`, `frontend/src/api/client.ts`,
  `frontend/src/api/problem.ts`, `frontend/src/api/types.ts`,
  `frontend/src/api/useCursor.ts`, `frontend/src/api/useGet.ts` — same-origin
  API, CSRF, paging and error client.
- `frontend/src/app/App.test.tsx`, `frontend/src/app/App.tsx`,
  `frontend/src/app/AuthProvider.tsx`, `frontend/src/app/ErrorBoundary.tsx`,
  `frontend/src/app/PresentationProvider.tsx`, `frontend/src/app/RequireAuth.tsx`,
  `frontend/src/app/Shell.tsx`, `frontend/src/app/auth-context.ts`,
  `frontend/src/app/navigation.ts`, `frontend/src/app/presentation-context.ts`
  — shell, routes, guards and presentation context.
- `frontend/src/components/PageCommon.tsx`, `frontend/src/components/format.ts`,
  `frontend/src/components/ui/Primitives.test.tsx`,
  `frontend/src/components/ui/Primitives.tsx`,
  `frontend/src/components/ui/toast-context.ts`,
  `frontend/src/i18n/I18nProvider.tsx`, `frontend/src/i18n/context.ts`,
  `frontend/src/i18n/messages.ts`, `frontend/src/index.css`,
  `frontend/src/main.tsx` — shared accessible UI and language scaffold.
- `frontend/src/pages/Alerts.tsx`, `frontend/src/pages/Dashboard.tsx`,
  `frontend/src/pages/Incidents.tsx`, `frontend/src/pages/Intel.tsx`,
  `frontend/src/pages/Login.tsx`, `frontend/src/pages/Pages.test.tsx`,
  `frontend/src/pages/Placeholder.tsx`, `frontend/src/pages/Response.tsx`,
  `frontend/src/pages/Settings.tsx`, `frontend/src/pages/Users.tsx`,
  `frontend/src/test/E2eRedaction.test.ts`, `frontend/src/test/Redacted.ts`,
  `frontend/src/test/setup.ts` — host pages, explicit placeholders and tests.
- `infra/Dockerfile.backend`, `infra/Dockerfile.e2e`,
  `infra/Dockerfile.frontend`, `infra/docker-compose.yml`,
  `infra/nginx/nginx.conf`, `infra/nginx/soc-site.conf`,
  `infra/nginx/tls.conf.example` — deployment images, network and Nginx.
- `scripts/bootstrap_dev_secrets.py`, `scripts/check_compose_isolation.py`,
  `scripts/provision_runtime.py`, `scripts/redact_compose_logs.py`,
  `scripts/run_compose_e2e.py` — explicit development bootstrap, host checks,
  runtime role, redacted diagnostics and disposable smoke.

### Pre-existing files modified and why

- `.env.example` — document the explicit development-cookie and proxy settings.
- `.github/workflows/ci.yml` — retain backend gates and add frontend, Compose,
  host/internal isolation and unchanged Playwright smoke checks.
- `.gitignore` — keep frontend builds and disposable artifacts out of Git.
- `README.md` — link the baseline guide and disclose its unapproved status.
- `backend/app/auth/csrf.py`, `backend/app/auth/dependencies.py`,
  `backend/app/auth/key_router.py`, `backend/app/auth/router.py`,
  `backend/app/auth/service.py`, `backend/app/auth/session.py` — consistently
  select the explicit dev-only cookie namespace while preserving secure defaults
  and domain-separating development session digests.
- `backend/app/core/config.py` — validate dev-cookie and exact trusted-proxy
  settings; `backend/app/core/http.py` — attribute only an explicitly trusted
  forwarded peer; `backend/app/core/openapi.py` — describe added host contracts.
- `backend/app/incidents/router.py`, `backend/app/users/router.py` — read the
  active cookie namespace for existing authenticated operations.
- `backend/app/main.py` — mount the host presentation/settings routes.
- `backend/app/response/router.py`, `backend/app/response/schemas.py` — expose
  role-protected command-log and Kill Switch reads and use the cookie selector.
- `backend/app/auth/legacy_roles.json` — record the authorized new host
  operations in the legacy role matrix.
- `backend/tests/contract/test_legacy_matrix.py` — enforce the expanded matrix;
  `backend/tests/integration/test_host_migrations.py`,
  `backend/tests/integration/test_pb2_migrations.py`,
  `backend/tests/integration/test_pb3_migrations.py` — account for additive
  migration 009 while preserving earlier migration coverage.
- `backend/tests/unit/test_ci_isolation.py` — cover bridge task cleanup and
  exception propagation; `backend/tests/unit/test_config.py` — cover secure
  defaults, development-cookie restrictions and exact proxy validation.
- `docs/governance/PROGRESS.md` — record task evidence, failures, decisions and
  the pending baseline gate; `docs/governance/config.md` — document new settings,
  worker entrypoint and host-isolation procedures.
- `infra/secrets/README.md` — explain explicit dev bootstrap and operator-owned
  production secret files; `openapi.host.json` — regenerate the host contract.
- `pyproject.toml`, `requirements.lock` — pin Gunicorn/uvicorn-worker and their
  hashes; set the host isolation check's Ruff target to Python 3.10.
- `scripts/ci_isolated_checks.py` — close active relay tasks deterministically
  and surface bridge errors without weakening the no-IP assertion.
