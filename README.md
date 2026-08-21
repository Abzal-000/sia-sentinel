# SIA Sentinel — Proof-of-Savings Protocol

**An independent, cryptographically verifiable audit layer for AI cost optimization.**

Every vendor claims their cheaper model "works just as well." Nobody can prove it —
and nobody trusts the vendor's own benchmark. SIA Sentinel is the neutral auditor:
it replays your real workload against the candidate configuration, proves (or
disproves) quality equivalence with statistical guarantees, and issues a signed,
tamper-evident receipt that both sides of the deal can verify independently.

This is not an AI wrapper. The core product is a **verification and attestation
protocol**: reproducibility manifests, Wilson confidence intervals for equivalence,
Ed25519-signed receipts, and a hash-chained public ledger (TrustChain) with
periodic signed checkpoints.

---

## What it does

| Capability | Description |
|---|---|
| **Code audits** | Prove a refactor (e.g. recursive → iterative) preserves behavior, then quantify compute savings |
| **LLM flow audits** | Replay a prompt dataset through old/new model configs; equivalence via Wilson CI on pass-rate, savings from token pricing |
| **Savings Autopilot** | Screen a model catalog (by tier/pricing), find the cheapest config that preserves quality, then prove it with a full final audit |
| **TrustChain ledger** | Append-only hash chain of all receipts, signed checkpoints, tamper detection, public attestations + embeddable SVG badges |
| **Multi-tenant SaaS** | Tenant isolation for jobs/receipts/invoices, RBAC (API keys + JWT), usage metering |
| **Billing** | Plans with monthly quotas (hard cap on free, billed overage on paid), invoice generation per period |

### Proof, not vibes

An audit claim is only *verified* when the equivalence test passes with a
confidence guarantee:

- **Wilson score confidence interval** on the new config's pass rate — the claim
  holds when the CI lower bound clears the quality floor, not just the point estimate.
- **Reproducibility manifest** — dataset hash, config hash, benchmark seeds are
  pinned into the receipt, so the claim can be independently re-run.
- **Ed25519 receipt** — signed by the auditor; anyone with the public key can
  verify it without trusting the service.
- **Hash-chained registry** — each receipt links to the previous one; rewriting
  history breaks the chain. Checkpoints anchor the chain state periodically.

## Public Attestation Network

Attestations are a portable standard, not an internal artifact: any external
system can independently verify a savings claim without trusting the service.

- **Spec:** [`docs/attestation-spec.md`](docs/attestation-spec.md) (spec id
  `sia-attestation/1`, carried in every document) with a machine-readable
  [`docs/attestation.schema.json`](docs/attestation.schema.json).
- **Independent verifier:** [`sia-verifier`](verifier/) — a standalone package
  (`pip install sia-verifier`, single dependency: `cryptography`) that verifies
  any attestation **without trusting the auditor**: Ed25519 receipt signature,
  claim consistency, TrustChain hash chain, checkpoints. No network calls.

  ```bash
  sia-verifier attestation.json --chain registry.jsonl
  ```

  Walkthrough: [`docs/verify-in-5-minutes.md`](docs/verify-in-5-minutes.md).
- **Verification portal:** `GET /attestations/{id}` renders a human verdict
  (signature ✓/✗, chain ✓/✗, claim, badge embed snippet); `GET /registry` is
  the public HTML index.
- **Opt-in public registry:** tenants publish via
  `POST /v1/tenants/{id}/settings` (`publish_attestations: true`); only opted-in
  records appear in `GET /v1/attestations`. Individual attestations stay
  reachable by id (badges link to them).
- **Embed the badge:**

  ```html
  <img src="https://sentinel.example.com/v1/attestations/{id}/badge.svg"
       alt="Proof-of-Savings attestation" />
  ```

- **Outbound webhooks:** subscribe a URL to `audit.completed` / `audit.failed`
  via `POST /v1/webhooks/subscriptions`. Deliveries are POSTed with an
  `X-SIA-Signature` header — HMAC-SHA256 over the raw body using the
  subscription secret (returned once at creation). Verify it to trust the
  sender:

  ```python
  import hmac, hashlib
  expected = "sha256=" + hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
  assert hmac.compare_digest(expected, request.headers["X-SIA-Signature"])
  ```

---

## Quick start (dev)

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

uvicorn sentinel.api:app --reload                 # API on http://localhost:8000
python -m unittest discover -s tests              # run the test suite
```

Interactive docs: `http://localhost:8000/docs`

### Run an audit (CLI)

```bash
# Simulated LLM-flow audit (no API keys needed)
python audit_cli.py audit --flow flows/example_llm_flow.json

# Live audit against NVIDIA NIM (set NVIDIA_API_KEY in .env, never inline)
python audit_cli.py audit --flow flows/live_llm_flow.json

# Savings Autopilot: pick the cheapest config that still passes
python audit_cli.py optimize --flow flows/live_optimize.json
```

### Run an audit (Python SDK)

```python
from sia_sentinel import SentinelClient

client = SentinelClient("http://localhost:8000", api_key="sk-...")
result = client.run_audit(flow)
print(result["registry_id"], result["receipt"]["safety_approved"])

# Async + Autopilot
audit_id = client.submit_optimization(flow)
snapshot = client.wait_for_optimization(audit_id)
```

SDK source: [`sdk/sia_sentinel/`](sdk/sia_sentinel/) — pure `httpx`, no server-side imports.

### Self-service onboarding

New customers register without any operator involvement:

```python
from sia_sentinel import SentinelClient

# Creates the tenant (free plan) and returns a client holding its first
# admin API key — shown once, store it securely.
client = SentinelClient.signup("https://sentinel.example.com", "Acme Corp")
client.run_audit(flow)

# The tenant admin then manages its own keys:
client.create_tenant_key("acme", "ci-key", role="user")
```

Privilege model: a **platform admin** (operator) manages all tenants, plans,
checkpoints and global keys; a **tenant admin** (the key returned by signup)
manages only its own tenant — keys, settings, webhooks, invoices viewing.
Tenant admins cannot see other tenants or change plans.

---

## API overview

| Endpoint | Auth | Description |
|---|---|---|
| `POST /v1/audit` | user | Synchronous audit → signed receipt + registry entry |
| `POST /v1/audits` | user | Async audit (persistent queue, crash recovery) |
| `GET /v1/audits/{id}` | user | Job status (tenant-isolated) |
| `POST /v1/optimize` | user | Savings Autopilot run (async) |
| `GET /v1/optimize/{id}` | user | Optimization status |
| `GET /v1/receipts` / `GET /v1/receipts/{id}` | public | Receipt registry |
| `GET /v1/ledger/head` / `GET /v1/ledger/verify` | public | TrustChain state / full chain verification |
| `POST /v1/ledger/checkpoint` | platform admin | Anchor a signed checkpoint |
| `GET /v1/attestations/{id}` | public | Portable attestation document |
| `GET /v1/attestations` | public | Public registry (opt-in tenants only) |
| `GET /v1/attestations/{id}/badge.svg` | public | Embeddable "verified savings" badge |
| `GET /attestations/{id}` / `GET /registry` | public | Verification portal (HTML) |
| `POST /v1/signup` | public | Self-service onboarding (tenant + first admin key) |
| `POST /v1/tenants/{id}/settings` | tenant/platform admin | Tenant settings (publish opt-in) |
| `POST/GET/DELETE /v1/tenants/{id}/api-keys` | tenant/platform admin | Tenant-scoped key management |
| `POST/GET/DELETE /v1/webhooks/subscriptions` | user | Outbound webhook subscriptions |
| `POST /v1/tenants` / `GET /v1/tenants` | platform admin | Tenant management |
| `POST/GET/DELETE /v1/auth/api-keys` | platform admin | Global key management |
| `GET /v1/usage` | user | Usage summary (billing basis) |
| `GET /v1/billing/plans` | public | Plan catalog |
| `GET /v1/billing/plan` / `POST /v1/billing/plan` | user / platform admin | Current quotas / plan change |
| `POST /v1/billing/invoices` / `GET /v1/billing/invoices` | platform admin / user | Invoice issue / list |

Quota enforcement: exceeding the monthly limit on a hard-cap plan returns
`402 Payment Required` with an upgrade hint. Paid plans allow overage, which is
itemized on the period invoice.

---

## Production deployment

```bash
export JWT_SECRET_KEY=$(openssl rand -hex 32)
export RECEIPT_SIGNING_KEY=$(openssl rand -hex 32)
export EVIDENCE_SIGNING_KEY=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)

docker compose -f docker-compose.prod.yml up -d
```

`docker-compose.prod.yml` runs Sentinel + PostgreSQL. **All secrets are required
with no defaults** — compose refuses to start without them. Runtime data
(receipts, tenants, usage, invoices, API keys) lives on the `sentinel_data`
volume; configure locations via `RECEIPTS_DIR`, `TENANTS_FILE`,
`USAGE_EVENTS_FILE`, `INVOICES_FILE`, `API_KEYS_FILE`.

Dev compose (SQLite, no required secrets): `docker compose up`.

---

## Security model

- **No secrets in code.** Signing keys come from env vars; if missing, the
  service generates an ephemeral key and prints a loud warning (receipts won't
  survive restarts — acceptable in dev only).
- **Demo login is off by default** (`ENABLE_DEMO_LOGIN`); demo credentials are
  for local evaluation only.
- **Live LLM credentials** are referenced by env var name in flows
  (`api_key_env`), never inlined into flow files or requests.
- **Tenant isolation** on jobs, receipts metadata, and invoices; RBAC roles:
  `admin`, `verifier`, `user`, `anonymous`.
- Gitignored runtime artifacts: `*.db`, `tenants.json`, `usage_events.jsonl`,
  `api_keys.json`, `invoices.json`, `receipts/`, `identities/`, `.env`.

## Project layout

```
sia/            Audit engine: flows, optimizer, model catalog, Wilson CI
sentinel/       API service: auth, tenancy, billing, jobs, receipts, ledger, webhooks
sdk/            Client SDK (sia_sentinel)
flows/          Flow declarations (code | llm_flow | optimize)
docs/           Attestation spec + JSON Schema
tests/          480 tests (unittest)
dashboard/      Streamlit dashboard
audit_cli.py    CLI: audit / optimize / sign / verify
```

## Status

Prototype-stage, fully working core: live pilots against NVIDIA NIM endpoints
have verified real savings claims; the test suite (480 tests) covers the audit
engine, ledger, tenancy, billing, jobs persistence, public attestation network,
self-service onboarding, and the SDK. See `SECURITY_REPORT.md` for the security review.
