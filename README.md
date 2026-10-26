# NHI Runtime Decision-Rights

Reference implementation for non-human identity (NHI) runtime decision-rights, companion to **OWASP SPVS V1.3.7** work and to the `aisvs-action-class-reference` repo.

Where the AISVS reference covers the **action class** side of the gate, this repo covers the **identity provenance** side. Together they specify the floor for the write side of agentic AI: classification declared upstream, identity provenance verified at runtime, both feeding one deterministic gate.

## What this repo provides

- **`schema/nhi-manifest.schema.json`** — JSON Schema for an NHI manifest. Declares the identity type, provenance (issuer / subject / audience), permitted actions, and freshness constraints.
- **`schema/examples/`** — sample manifests for service accounts, CI pipeline tokens, and workload identity federation.
- **`gate/nhi_runtime_gate.py`** — reference NHI runtime gate. Verifies identity provenance at action time and checks the action against the manifest.
- **`tests/`** — pytest test cases.

## The architectural cut

NHI runtime decision-rights pair with action-class authority. Action class says **what the agent is allowed to do** (AISVS C9.2.3 / C9.2.4 / C9.2.10). NHI provenance says **what identity the agent is operating under, right now**.

Two failure modes the manifest is meant to catch:

1. The credential was issued legitimately but is being used after rotation or revocation.
2. The identity is correct but is being used outside its intended audience or time window.

The gate refuses any action where:

- The identity is not declared in the NHI manifest.
- The token freshness exceeds the declared `max_age_seconds`.
- The audience does not match the declared audience.
- The action requested is not in the `permitted_actions` list for this identity.

## NHI types supported

| Type | Example |
|---|---|
| `service_account` | Static service-account credential (Vault-issued, K8s ServiceAccount token) |
| `ci_pipeline_token` | Short-lived OIDC token from GitHub Actions, GitLab, Jenkins, etc. |
| `workload_identity_federation` | SPIFFE / WIF token bridging workload identity to cloud APIs |
| `agent_credential` | Long-lived agent identity with bounded permissions |

## Quick start

```bash
git clone https://github.com/Mayur021/nhi-runtime-decision-rights.git
cd nhi-runtime-decision-rights
python3 -m pytest tests/
```

Then look at:

- `schema/examples/ci-pipeline-token.json` for a typical GitHub Actions OIDC manifest
- `gate/nhi_runtime_gate.py` for the runtime gate

## Pairing with AISVS reference

This repo is designed to be used together with `aisvs-action-class-reference`. The AISVS gate decides what action class is permitted. The NHI gate decides whether the calling identity is authorized to invoke that action class right now. Both must pass.

```
   Agent attempts action
            │
            ▼
   ┌─────────────────────┐
   │  NHI runtime gate   │  ←  identity provenance + freshness + audience
   │  (this repo)        │
   └──────────┬──────────┘
              │ identity ok
              ▼
   ┌─────────────────────┐
   │  Action-class gate  │  ←  manifest-declared class + worst-case chain
   │  (AISVS reference)  │
   └──────────┬──────────┘
              │ class ok
              ▼
        Action executes
```

## License

CC-BY-4.0.

## Related work

 - [Action-Class Authority for AI Agents: A Verification-Side Reference](https://github.com/Mayur021/action-class-authority) — Whitepaper v1.0 (June 2026). Chapter 8 covers the joint chain-level audit schema (six properties, with Mallikarjunarao Sunke) that this NHI runtime gate operationalizes. Anchored in OWASP AISVS C9.2.3, C9.2.4 and C9.2.10, shipped in v1.0 and CSA Defining Non-Human Identity (under IAM WG review).
- OWASP SPVS V1.3.7 (NHI runtime decision-rights, work in progress).
- OWASP AISVS C9.2.6 / C9.2.7 (action-class authority).
- SPIFFE / SPIRE for cryptographic workload identity.
- Workload Identity Federation (cross-cloud and across-issuer patterns).

## Author

Mayur Agnihotri. LinkedIn: [linkedin.com/in/mayuragnihotri](https://www.linkedin.com/in/mayuragnihotri/). GitHub: [@Mayur021](https://github.com/Mayur021).
