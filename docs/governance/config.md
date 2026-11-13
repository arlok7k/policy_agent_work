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

For each pair, setting both is an error rather than choosing precedence. Secret
files are read as UTF-8; one terminal newline is stripped. Length validation
cannot establish entropy: operators must provision a random value. Do not commit
or log secret values. Test secrets are generated at runtime and discarded.

Alembic reads only `DATABASE_URL` or `DATABASE_URL_FILE`; it does not require the
session-signing secret. Run upgrades with `make migrate` after provisioning the
database URL. Never run a downgrade against a non-disposable database.

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
