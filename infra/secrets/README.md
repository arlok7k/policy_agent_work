# Docker secrets and local development

Production secrets are provisioned by the operator; never commit them. The
Compose migration job receives the owner and runtime database URLs. The API,
worker and Beat receive only the restricted runtime URL, webhook HMAC and
session-signing secret. Postgres receives its owner password as a separate file;
the migration job also has that credential inside the owner database URL.

For disposable local development only, explicitly run from the repository root:

```sh
ENV=development python3 scripts/bootstrap_dev_secrets.py
```

This refuses to overwrite any of its files. It writes ignored files below
`infra/secrets/dev/` and never prints their values. The host directory has mode
0700. File-backed Compose secrets are bind mounts: their UID/mode remapping is
not honored by local Compose, so these *development-only* files are mode 0444
inside a directory inaccessible to other unprivileged host users. Docker
administrators and root can still read them. Do not reuse them in production.
They are throwaway data, not backup material. If they are lost or changed,
existing PostgreSQL volumes will not automatically change their credentials;
never delete a persistent database to make the bootstrap succeed.

Production operators must provide distinct files and set the corresponding
`SOC_*_FILE` Compose variables: `SOC_POSTGRES_PASSWORD_FILE`,
`SOC_MIGRATOR_DATABASE_URL_FILE`, `SOC_RUNTIME_DATABASE_URL_FILE`,
`SOC_WEBHOOK_SECRET_FILE` and `SOC_SESSION_SIGNING_SECRET_FILE`. The Postgres
password must match the owner URL; both database URLs must target the same
Postgres database, and the runtime URL must name a distinct unprivileged login.
Provision file permissions so the respective non-root container users can read
the bind mounts. Never use the development opt-in flag in production.
