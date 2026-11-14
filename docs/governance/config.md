# Backend configuration

PB1 reads process environment variables at startup; it does not implicitly read
`.env`. Copy `.env.example` outside version control and export its settings, or
use Docker secret files. Missing or invalid settings prevent the service from
starting. Configuration failures do not print supplied values.

| Key | Required | Meaning |
|---|---|---|
| `ENV` | Yes | `development`, `test`, or `production`. |
| `DATABASE_URL` / `DATABASE_URL_FILE` | Exactly one | SQLAlchemy PostgreSQL URL using `postgresql+psycopg`. The URL may contain credentials and is treated as secret. |
| `SESSION_SIGNING_SECRET` / `SESSION_SIGNING_SECRET_FILE` | Exactly one | Cryptographically random secret with at least 32 bytes of entropy, supplied by an operator. |
| `SESSION_TTL_SECONDS` | Yes | Positive session lifetime; example 28800. |
| `LOGIN_FAILURE_LIMIT`, `LOGIN_WINDOW_SECONDS` | Yes | Positive per-source and per-account failure limit and window; examples 5 and 60. |
| `PASSWORD_MIN_CHARS`, `PASSWORD_MAX_CHARS` | Yes | Positive password policy bounds; examples 14 and 1024, with minimum no greater than maximum. |
| `DEFAULT_PAGE_SIZE`, `MAX_PAGE_SIZE` | Yes | Positive pagination bounds; example 50 and 100, with default no greater than maximum. |
| `USERNAME_MAX_CHARS` | Yes | Positive upper bound for normalized usernames; example 128. |
| `API_KEY_NAME_MAX_CHARS` | Yes | Positive upper bound for API-key names; example 128. |
| `MAX_API_KEY_TTL_SECONDS` | Yes | Positive maximum API-key lifetime; example 2592000. |
| `WEBHOOK_SECRET_FILE` | Yes | Path to an operator-provisioned Docker secret containing at least 32 bytes; inline `WEBHOOK_SECRET` is rejected. |
| `WEBHOOK_INITIATOR` | Yes | Stable service identity, formatted `service:<name>`, attached to alert task headers. |
| `WEBHOOK_MAX_BODY_BYTES`, `WEBHOOK_MAX_FIELD_CHARS` | Yes | Positive webhook byte and text-field caps; examples 262144 and 512. |
| `WEBHOOK_MAX_CLOCK_SKEW_SECONDS` | Yes | Positive symmetric timestamp tolerance; example 300. |
| `REDIS_TIMEOUT_SECONDS` | Yes | Positive Redis connection and operation timeout; example 2. |
| `THREAT_INTEL_TIMEOUT_SECONDS` | Yes | Positive provider deadline; example 2. |
| `THREAT_INTEL_CACHE_TTL_SECONDS` | Yes | Positive cache lifetime; example 3600. |
| `THREAT_INTEL_BULK_MAX_ITEMS` | Yes | Positive maximum indicators per request; example 100. |
| `INCIDENT_MAX_ALERTS`, `INCIDENT_MAX_TEXT_CHARS` | Yes | Positive incident alert-count and text bounds; examples 100 and 4096. |
| `THROTTLE_CLEANUP_INTERVAL_SECONDS`, `THROTTLE_CLEANUP_BATCH_SIZE` | Yes | Positive scheduler interval and maximum rows per cleanup; examples 300 and 500. |
| `THROTTLE_CLEANUP_INITIATOR` | Yes | Stable `service:<name>` identity attached to scheduled cleanup tasks. |
| `CELERY_BROKER_URL` / `CELERY_BROKER_URL_FILE` | Exactly one | Redis broker URL; treated as a secret because it may contain credentials. |
| `REDIS_CACHE_URL` / `REDIS_CACHE_URL_FILE` | Exactly one | URL of a separate Redis cache instance; treated as a secret. |

The two Redis instances must be provisioned separately; the loader rejects
identical endpoints but cannot identify every possible DNS alias. Normal
`redis://`/`rediss://` URLs are supported, as are `redis+socket:///...` for the
broker and `unix:///...` for the cache. The application validates PB2 settings
at startup but does not claim Redis readiness until a request actually uses it.
The PB4 infrastructure has not yet been built. Start a worker with the same
required settings and restricted database login as the API:
`PYTHONPATH=backend <venv>/bin/celery -A app.jobs.worker:celery worker -Q default`.
Start one Beat process with the same configuration and a durable writable schedule
file, for example:

```sh
PYTHONPATH=backend <venv>/bin/celery -A app.jobs.worker:celery beat \
  --schedule=/var/lib/smart-soc/celerybeat-schedule
```

Provision that directory outside the repository. All API and worker replicas must share an identical
`LOGIN_WINDOW_SECONDS`; see [DR-022](../adr/DR-022.md) for the cleanup's locking,
bounds and configuration-drift risk. Stopping Beat leaves expired rows for later
cleanup but does not disable the login-time expiry check.
Broker access is a trust boundary: an initiator header is required, but is not
itself authenticated against a compromised broker. Tasks use late
acknowledgement and are redelivered on worker loss; other failures still require
operator monitoring and are not reported as successful persistence.

Webhook senders supply `X-Webhook-Timestamp` (Unix seconds), `X-Webhook-Id`
(canonical lowercase UUID) and `X-Webhook-Signature` (`sha256=` plus the HMAC
hex digest). The signed bytes are the timestamp, a dot, the UUID, a dot, then
the exact JSON body bytes. Event-ID replay reservations are volatile Redis
state; see [DR-016](../adr/DR-016.md) for the durability limitation, error
statuses and ambiguous publication behavior. Configure synchronized clocks.

For each pair, setting both is an error rather than choosing precedence. Secret
files are read as UTF-8; one terminal newline is stripped. Length validation
cannot establish entropy: operators must provision a random value. Do not commit
or log secret values. Test secrets are generated at runtime and discarded.

Alembic reads only `DATABASE_URL` or `DATABASE_URL_FILE`; it does not require the
session-signing secret. Run upgrades with `make migrate PYTHON=<venv-python>` after
provisioning the database URL. Never run a downgrade against a non-disposable
database.

Database tests require `TEST_DATABASE_URL` to point to a genuinely disposable
PostgreSQL database named with an `_test` suffix, plus
`TEST_DATABASE_DISPOSABLE=1`. Tests create and drop a private schema there. The
flag and suffix alone do not make a database disposable. Tests that create and
drop temporary PostgreSQL login roles also require a genuinely disposable cluster
and `TEST_PG_CLUSTER_DISPOSABLE=1`, since roles are cluster-wide. Missing settings
fail the tests rather than skipping them. Never point them at a shared cluster.

Migrations must run with a DDL-capable PostgreSQL principal able to create or
validate the non-login `hpb_app` role. The service must instead use a separate,
unprivileged login that inherits `hpb_app`. At startup the service verifies that
its login and effective role cannot mutate the activity log or own its table,
schema or database; unsafe or unavailable database access aborts startup.

HTTP responses include a safe UUIDv4 `X-Correlation-Id`. Application request
logs are JSON and omit bodies, headers, query strings and raw principal IDs;
activity events include the correlation ID. Deploy the server with access logs
disabled (for Uvicorn, `--no-access-log`) unless the server and proxy log formats
have been independently configured not to record raw URLs or credentials. Do not
turn on SQLAlchemy statement/parameter echo in a deployment.

`GET /api/health` is intentionally public per DR-013. It reports only database
readiness and no configuration or error details. Restrict network reachability
if exposing even this readiness bit is undesirable. Startup itself fails if the
required database or its runtime privileges are unavailable.

For a development-only initial seed, set `ENV=development`, use the restricted
runtime database login, and securely supply `SEED_ADMIN_PASSWORD`,
`SEED_SENIOR_ANALYST_PASSWORD` and `SEED_ANALYST_PASSWORD` in the process
environment. Passwords must satisfy the configured policy. Then run
`make seed-dev PYTHON=<python>`. The script refuses every non-development
setting and any nonempty user table, and creates all role-named accounts or
none. Do not put real passwords into version control, shell history or logs;
never point the development environment at a production database.
