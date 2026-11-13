# SMART SOC Governance Plane

This repository is being built in phases from the greenfield specification. The
reference documents are read-only:

- [Implementation Agent master prompt](policy_agent_work/AGENT_MASTER_PROMPT.md)
- [Policy, Controls & Permissions specification v2.1](policy_agent_work/POLICY_CONTROLS_PERMISSIONS_AGENT_SPEC.md)

Current phase and blockers: [progress](docs/governance/PROGRESS.md). Decisions:
[decision records](docs/adr/).

PB1 provides the backend foundation only. Later SOC functionality and the
Governance Plane are not yet implemented. See the phase progress before use.

## Run the backend

1. Install Python 3.15.2, create a virtual environment, and run `make install
   PYTHON=<venv-python>` to install the hash-pinned dependencies.
2. Provision PostgreSQL and the required settings and secrets as described in
   [backend configuration](docs/governance/config.md). Run `make migrate
   PYTHON=<venv-python>` with a DDL-capable database login. Have the database
   administrator provision a separate unprivileged login inheriting `hpb_app`,
   then configure the service with that runtime login instead of migration credentials.
3. For development only, provide the three seed passwords securely and run
   `make seed-dev PYTHON=<venv-python>`. The seed refuses a non-development
   environment or a nonempty user table.
4. Start the API with `PYTHONPATH=backend <venv-python> -m uvicorn app.main:app
   --host 0.0.0.0 --port 8000 --no-access-log`. Use an operator-provided TLS
   reverse proxy: session cookies are `Secure` and require HTTPS. The PB4 proxy
   and deployment stack have not been built yet.

For verification, configure a genuinely disposable PostgreSQL database and
cluster as documented, then run `make check` and `make audit` with the same
virtual-environment Python.
