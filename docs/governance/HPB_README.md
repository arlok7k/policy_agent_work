# Host Platform Baseline: operator guide

The HPB is a **baseline under review**, not a production-ready SOC or an
approved Governance Plane. Its integrations and response commands are simulated.
See [progress](PROGRESS.md), the [legacy authorization matrix](../../backend/app/auth/legacy_roles.json),
[response decisions](../adr/DR-027.md), and the other [decision records](../adr/).
The PB4 owner gate has not been approved; do not start P0 on the strength of a
successful test alone.

## Prerequisites and boundaries

Use a stable **native Linux Docker Engine 28.0 or newer**, a local Docker Unix
socket, the Compose plugin, and Python 3.10 or newer for the host bootstrap and
verification scripts. The socket must connect to the Docker daemon on the same
host/network namespace as the host-side checks; do not use a forwarded socket,
remote daemon, Docker Desktop VM, or containerized client for this evidence.
Docker [1](https://docs.docker.com/engine/network/port-publishing/) warns that
older releases can expose loopback-published ports to the same layer-2 network.
The examples assume default `SOC_*` paths and ports, enough resources to build
the pinned images, and a fresh, disposable Compose project; the backend image
itself uses Python 3.15. This setup is **development-only and disposable**. The
default Nginx port is bound to `127.0.0.1:8080`; PostgreSQL and the separate
Redis broker and cache have no published ports. Only Nginx has an edge-facing
port.

The internal IPv4 bridge uses Docker's `isolated` gateway mode; IPv6 is disabled
on that network. Before starting and after it is healthy, run the checks below:
Compose alone does not enforce the host-side preflight. The runtime check inspects
actual container addresses and published ports, requires backend connections to
all three data services by name and address, requires host access to published
Nginx, and rejects host connections to each data service. It then repeats the
internal control. This measures the invoking host process, not every possible
host configuration; repeat it after daemon, network or deployment changes.
Docker administrators, root, and users who can change firewall/routing or
attach containers can bypass the boundary. Redis is unauthenticated inside the
network; do not treat this as isolation from compromised internal services. See
[DR-048](../adr/DR-048.md). The opt-in test client is not a production service.

The Compose migration service uses the owner database credential and provisions
a separate restricted runtime login. Backend, worker and Beat receive only
runtime credentials. The two Redis services have no authentication and hold
ephemeral data; a compromised internal service can access them, so network
isolation is not a defense against that threat. Broker access also permits task
publication; an initiator header is not an authenticated identity. Nginx is the
explicitly trusted proxy at `172.30.42.2`; the dynamic address pool starts at
`172.30.42.128/25`. If this subnet conflicts with a host network, change subnet,
static IP, dynamic pool and exact proxy trust consistently; see
[DR-039](../adr/DR-039.md) and [DR-044](../adr/DR-044.md).

## Start a disposable local stack

From the repository root in a Bash shell:

```sh
export ENV=development DEV_INSECURE_COOKIES=true
python3 scripts/bootstrap_dev_secrets.py
python3 scripts/check_compose_isolation.py preflight
docker compose -f infra/docker-compose.yml config --quiet
docker compose -f infra/docker-compose.yml up --build --wait --wait-timeout 300
python3 scripts/check_compose_isolation.py verify
docker compose -f infra/docker-compose.yml ps -a
curl --fail --silent --show-error http://127.0.0.1:8080/api/health
```

Open `http://127.0.0.1:8080`. The migration container should exit successfully;
the remaining normal services should be healthy. The explicit bootstrap creates
ignored throwaway secret files and **refuses to overwrite** any of them. Do not
regenerate them against a retained database: the database password is not
rotated automatically. See [secrets guidance](../../infra/secrets/README.md).

`DEV_INSECURE_COOKIES=true` selects separate non-Secure development cookie names
for HTTP only; it is rejected outside development. Without this explicit opt-in,
Secure `__Host-` cookies require HTTPS. Never expose this HTTP development setup
to an untrusted network or reuse its secrets in production.

**Do not proceed if either isolation check fails.** Preflight rejects an
unsupported engine, a remote/ambiguous Docker context, and a pre-existing data
network whose mode, IP version or IPAM allocation does not match this Compose
file. The post-start check also rejects extra data-service networks, published
ports, unreachable positive controls, and any successful host connection. It does
not modify networks, containers, or volumes.

If a pre-existing network is stale (for example, an ordinary bridge from an
older revision), first identify and stop only the intended stack with
`docker compose -f infra/docker-compose.yml down`, then rerun preflight and
startup to recreate the network. This command retains named volumes; other
attached containers can prevent network removal and must be investigated. Never
use `down --volumes` on data you need to keep. If both `DOCKER_HOST` and
`DOCKER_CONTEXT` are set, unset the unintended override before checking.

## Seed initial development users

The seed is development-only and refuses any nonempty user table. It creates
`admin`, `senior_analyst` and `analyst`, with independent passwords supplied by
the operator; the default policy requires at least 14 characters. Do not place
passwords in shell history, command arguments, logs or the repository. For an
interactive Bash session, for example:

```sh
read -r -s -p 'Admin password: ' SEED_ADMIN_PASSWORD; printf '\n'
read -r -s -p 'Senior analyst password: ' SEED_SENIOR_ANALYST_PASSWORD; printf '\n'
read -r -s -p 'Analyst password: ' SEED_ANALYST_PASSWORD; printf '\n'
export SEED_ADMIN_PASSWORD SEED_SENIOR_ANALYST_PASSWORD SEED_ANALYST_PASSWORD
docker compose -f infra/docker-compose.yml exec -T \
  -e SEED_ADMIN_PASSWORD -e SEED_SENIOR_ANALYST_PASSWORD -e SEED_ANALYST_PASSWORD \
  backend python scripts/seed_dev.py
unset SEED_ADMIN_PASSWORD SEED_SENIOR_ANALYST_PASSWORD SEED_ANALYST_PASSWORD
```

Environment values can still be observed by the host user and Docker
administrators. Use a trusted machine and distinct throwaway passwords. The
Playwright harness seeds its own credentials and must therefore use a **fresh,
empty disposable** user table instead of a manually seeded one.

## Send a signed sample webhook

For a local development stack only, this example reads the ignored webhook
secret file without printing it. It signs exactly the UTF-8 body it sends:

```sh
python3 - <<'PY'
import hashlib, hmac, json, os, time, urllib.request, uuid
from pathlib import Path

secret_file = Path(os.environ.get('SOC_WEBHOOK_SECRET_FILE', 'infra/secrets/dev/webhook_secret'))
key = secret_file.read_text(encoding='utf-8').removesuffix('\n').removesuffix('\r').encode('utf-8')
event = str(uuid.uuid4())
timestamp = str(int(time.time()))
body = json.dumps({
    'source': 'local-demo', 'rule_id': 'sample-rule', 'severity': 'high',
    'agent': '004', 'src_ip': '8.8.8.8', 'raw': {'message': 'Example alert'},
}, separators=(',', ':')).encode('utf-8')
message = timestamp.encode('ascii') + b'.' + event.encode('ascii') + b'.' + body
signature = 'sha256=' + hmac.new(key, message, hashlib.sha256).hexdigest()
request = urllib.request.Request(
    'http://127.0.0.1:8080/api/alerts/webhook', data=body, method='POST',
    headers={'Content-Type': 'application/json', 'X-Webhook-Timestamp': timestamp,
             'X-Webhook-Id': event, 'X-Webhook-Signature': signature},
)
with urllib.request.urlopen(request, timeout=10) as response:
    print('Webhook HTTP status:', response.status)
PY
```

The signed bytes are `timestamp + '.' + canonical-lowercase-UUID + '.' + body`,
using HMAC-SHA256 and a lowercase `sha256=<hex>` header. The default timestamp
skew is 300 seconds and an event ID cannot be replayed within the reservation
window. HTTP 202 means the alert was queued, not that it is already visible or
durably stored. Repeated alert content may deduplicate even with a new event ID.
The development Redis broker is ephemeral; this is not a production-grade
ingestion durability guarantee.

After seeding and sending the sample, sign in as `analyst`, open the alert from
**Alerts**, and choose **Investigate alert**. From the incident, select **Request
response**, choose `isolate_host`, and use the sample agent and IP. The request
remains pending until a different `senior_analyst` or `admin` signs in and
approves it in **Response**. Use **Refresh activity** to check the actual
simulated record in the executed-command log. The Kill Switch controls are also
on that page; an authorized operator can disengage it after a manual exercise.
These steps never isolate a real host.

## Tests and disposable smoke

CI validates Compose and the host/internal connectivity controls, and runs the
full backend suite with IP networking explicitly disabled, migration/contract
checks, dependency/license/secret scans, frontend checks and the Playwright smoke.
To reproduce the browser workflow, start and verify a **fresh disposable**
development stack as above, without manually seeding users, then run:

```sh
ENV=development DEV_INSECURE_COOKIES=true \
  python3 scripts/run_compose_e2e.py --disposable
```

This builds an opt-in Chromium test image, creates three throwaway users in the
empty database, sends signed alerts, approves a simulated L3 action, and **leaves
the Kill Switch engaged**. It also creates many test alerts. It must not be run
against production or a development database containing useful data. The script
never deletes volumes. If you explicitly choose to discard a disposable stack,
first verify the target Compose project and data, then remove its volumes with
`docker compose -f infra/docker-compose.yml down --volumes --remove-orphans`.
Do not use that destructive command on a persistent deployment.

For frontend-only checks with the pinned Node version:

```sh
cd frontend
npm ci
npm run lint && npm run typecheck && npm test && npm run build
npm audit --audit-level=low
```

For backend checks, install the hash-locked Python 3.15 dependencies and use
`make check` and `make audit`. Integration/migration tests require explicitly
marked **disposable** PostgreSQL and two Redis instances. The CI-equivalent
`scripts/ci_isolated_checks.py` additionally requires Linux namespace support,
`sudo`/`unshare`, and disposable service ports; see
[configuration](config.md) and the [CI workflow](../../.github/workflows/ci.yml).
Never point test or migration-reversal commands at a persistent database.

## Production preparation is operator work

Provision all secret files outside this repository and mount them for the
specified non-root container users. Set `ENV=production` and **unset**
`DEV_INSECURE_COOKIES` entirely. Provision a certificate and private key outside
this repository; mount them and the reviewed
[example TLS server](../../infra/nginx/tls.conf.example) into Nginx, and publish
its TLS port through an operator-reviewed Compose override. The example is not
active by default and does not disable the separate HTTP listener; restrict or
replace that listener in a reviewed deployment. HSTS only takes effect after a
successful HTTPS response. Use appropriate certificate permissions, firewalling,
monitoring, backup/restore and credential rotation. The Secure, host-only
`__Host-soc_session` and `__Host-soc_csrf` cookies are the production defaults.
No certificates, private keys or production hosting are supplied here.

## Behavior and known limitations

- All active legacy users may read alerts, incidents, response state and the
  read-only presentation projection, and may request actions. Only senior
  analysts or admins may approve/reject, request rollback or change the Kill
  Switch; manual L2 and all L3 approvals require a different eligible user.
  Users, API keys and administrative settings are admin-only. UI hiding is not
  authorization: the API enforces the same boundaries.
- L2 actions have a bounded TTL (default one hour, hard ceiling 24 hours).
  Automatic execution and TTL rollback pause while the Kill Switch is engaged;
  authorized human-approved actions can continue. Beat and the worker must be
  healthy for recovery. Pending approvals do not expire by default; review
  [DR-028](../adr/DR-028.md)–[DR-033](../adr/DR-033.md).
- Threat intelligence is a deterministic mock; VirusTotal, AbuseIPDB and OTX
  classes are deliberately unconfigured. The host AI provider is a mock and
  never calls an LLM. Wazuh-shaped and internal response connectors record
  simulated commands and never contact real endpoints.
- Real detection, correlation, UEBA, MITRE mapping, analytics and reporting are
  not implemented. MITRE, analytics, reports, toolkit and policies are labelled
  placeholders. English/Arabic and RTL/LTR are a shell scaffold, not complete
  page translation. The Governance Plane and later phases are not implemented.
- A database from an earlier unmerged PB3 development revision may not match the
  final migration schema. Do not rebuild persistent data to get past this; see
  [DR-033](../adr/DR-033.md) for the required reviewed migration approach.
