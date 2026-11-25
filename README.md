# SMART SOC Governance Plane

This repository is being built in phases from the greenfield specification. The
reference documents are read-only:

- [Implementation Agent master prompt](policy_agent_work/AGENT_MASTER_PROMPT.md)
- [Policy, Controls & Permissions specification v2.1](policy_agent_work/POLICY_CONTROLS_PERMISSIONS_AGENT_SPEC.md)

The Host Platform Baseline includes the API, simulated response domain, frontend
and Compose infrastructure. **PB4 remains subject to its human approval gate;**
the Governance Plane is not yet implemented or approved for P0.

- [Run, seed and test the host baseline](docs/governance/HPB_README.md)
- [Current phase, test results and blockers](docs/governance/PROGRESS.md)
- [Host configuration](docs/governance/config.md)
- [Decision records](docs/adr/)

The development stack uses throwaway secrets and an explicit insecure-HTTP
cookie opt-in. It is not a production deployment. Follow the operator guide for
TLS, secret handling, disposable test data and the list of simulated features.
