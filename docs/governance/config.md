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
flag and suffix alone do not make a database disposable. Missing settings fail
the tests rather than skipping them.
