# SIA Proof-of-Savings Attestation — Specification v1

**Spec identifier:** `sia-attestation/1` (carried in the `spec` field of every attestation document)
**Status:** implemented in `sentinel/` (SIA Sentinel). Machine-readable schema: [`attestation.schema.json`](attestation.schema.json).

An *attestation* is a portable, independently verifiable document proving that a
Proof-of-Savings claim (code refactor or LLM model switch) was audited by a
Sentinel instance, what the outcome was, and that the record is anchored in a
tamper-evident ledger.

## 1. Attestation document

Served at `GET /v1/attestations/{registry_id}` (public, no authentication).

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Always `"1"` for this spec. |
| `spec` | string | Spec identifier, `"sia-attestation/1"`. |
| `attestation_id` | string | Registry entry id (32 hex chars). |
| `issued_at` | string (ISO-8601 UTC) | When the receipt was registered. |
| `issuer.name` | string | Issuer display name. |
| `issuer.public_key` | string | Base64 **raw** 32-byte Ed25519 public key. |
| `issuer.algorithm` | string | Fixed label `"Ed25519-SHA256"` (scheme is RFC 8032 Ed25519). |
| `subject.flow_name` | string \| null | Audited flow name. |
| `subject.kind` | string \| null | `code` \| `llm_flow` \| `optimize`. |
| `subject.mode` | string \| null | `simulated` \| `live`. |
| `claim.savings_verified` | bool \| null | Whether the savings claim passed verification. |
| `claim.savings_ratio` | number \| null | Verified savings ratio (0..1), when applicable. |
| `claim.paired` | object \| null | Paired-statistics methodology behind the verdict (§1.1). |
| `claim.preregistration` | object \| null | Preregistration commitment the run was checked against (§1.2). |
| `receipt` | object | The signed cryptographic receipt (section 2). |
| `verification.receipt_signature_valid` | bool \| null | Live signature check result. |
| `verification.ledger_chain_valid` | bool | Live hash-chain check result. |
| `verification.ledger_entries` | integer | Chain length at verification time. |

### 1.1 Paired statistics (`claim.paired`)

Quality preservation is decided by a **paired** test: the same dataset items
(or test suite, for `kind=code`) run against both the old and the new
configuration. The verdict methodology is published in the attestation:

| Field | Type | Description |
|---|---|---|
| `non_inferior` | bool | Non-inferiority verdict: Newcombe CI lower bound for `p_new − p_old` > `−delta`. |
| `delta` | number | Pre-declared non-inferiority margin (0 = no quality drop tolerated; default for deterministic code suites). |
| `mcnemar_p` | number | Exact McNemar two-sided p-value on discordant pairs. |
| `minimum_detectable_difference` | number | MDD at n pairs, α = 1−confidence, 80% power: the smallest quality drop this audit could have noticed. |
| `n_pairs` | integer | Number of paired observations. |
| `b_old_pass_new_fail` | integer | Discordant pairs where old passed and new failed. |
| `c_old_fail_new_pass` | integer | Discordant pairs where old failed and new passed. |
| `ci_lower`, `ci_upper` | number | Newcombe hybrid score interval for `p_new − p_old`. |

`savings_verified` requires quality preservation — `non_inferior = true`, or
zero discordance (`b = c = 0`, observed quality identical; the claim remains
honest given the published MDD) — **and** positive savings.

### 1.2 Preregistration (`claim.preregistration`)

For `llm_flow`/`optimize` flows the audit parameters are committed to the
ledger **before** the run (`POST /v1/preregistrations`, protocol
`sia-preregistration/1`), clinical-trial style: no post-hoc dataset swaps or
delta shopping. The attestation carries the commitment it was checked
against:

| Field | Type | Description |
|---|---|---|
| `dataset_sha256` | string | SHA-256 of the dataset (`prompt\|expect_contains` lines). |
| `delta` | number | The non-inferiority margin declared pre-run. |
| `metric` | string | Quality metric, currently `"expect_contains"`. |

The ledger entry ordering (preregistration `seq` < receipt `seq`) and the
commitment match are checkable via
`GET /v1/preregistrations/{id}/verify/{registry_id}`.

**Access model.** Individual attestations are public by design: badges and
external verifiers link to them by id, so *knowing the id grants read access*.
The public *index* (`GET /v1/attestations`) lists only attestations of tenants
that opted in (`publish_attestations = true`).

## 2. Receipt and signature

A receipt binds a claim to the audited artifact:

| Field | Type | Description |
|---|---|---|
| `receipt_id` | string | SHA-256 hex of `evidence_id + time` at issuance. |
| `evidence_id` | string | Evidence record identifier (`audit-<flow_name>`). |
| `code_hash` | string | SHA-256 hex of the audited artifact serialization (the full audit report JSON for flow audits). |
| `safety_approved` | bool | `true` iff the savings claim was verified. |
| `trust_level` | string | Issuer trust label (currently `"JUNIOR"`). |
| `timestamp` | number | Unix epoch seconds at issuance. |
| `nonce` | string | SHA-256 hex of `timestamp + receipt_id`. |
| `signature` | string | Base64 Ed25519 signature (below). |
| `manifest` | object \| null | Optional reproducibility manifest (environment, dataset/config hashes, seeds, pricing) — **covered by the signature when present**. |

### 2.1 Commitment construction

The signed commitment is the **canonical JSON** serialization of:

```json
{
  "receipt_id": "...",
  "evidence_id": "...",
  "code_hash": "...",
  "safety_approved": true,
  "trust_level": "JUNIOR",
  "timestamp": 1724000000.0,
  "nonce": "...",
  "manifest": { ... }   // included only when manifest is not null
}
```

`receipt_id` is part of the commitment so a signature cannot be lifted off
one receipt and replayed against a different `receipt_id`.

Canonical JSON = `json.dumps(obj, sort_keys=True, separators=(",", ":"))`,
UTF-8 encoded. The signature is Ed25519 (RFC 8032) over those bytes,
base64-encoded.

### 2.2 Independent verification

Given only the attestation document:

1. Rebuild the commitment object from `receipt` fields exactly as in §2.1.
2. Verify the Ed25519 `signature` over the commitment bytes using
   `issuer.public_key` (base64 raw 32-byte key; reject anything else).
3. Check claim consistency: `claim.savings_verified` must equal the signed
   `receipt.safety_approved`. The `verification.*` fields are the server's
   live opinion and are **not** evidence — ignore them.

**Reference implementation:** the standalone [`sia-verifier`](../verifier/)
package (`pip install sia-verifier`), which verifies attestations with no
trust in the auditor and no network calls. The issuer-side signer lives in
`sentinel/cryptographic_receipts.py` (`ReceiptVerifier.verify`).

## 3. TrustChain ledger

Receipts are registered into an append-only hash chain
(`sentinel/receipt_registry.py`). Each entry:

| Field | Description |
|---|---|
| `seq` | 1-based position in the chain. |
| `prev_hash` | `entry_hash` of the previous entry; genesis = `"0" * 64`. |
| `registry_id` | Entry identifier (== `attestation_id`). |
| `registered_at` | ISO-8601 UTC registration time. |
| `receipt` | The receipt object. |
| `metadata` | Entry metadata (tenant_id, flow_name, kind, mode, claim fields). |
| `entry_hash` | SHA-256 hex of the canonical JSON of `{seq, prev_hash, registry_id, registered_at, receipt, metadata}`. |

**Chain verification** (`GET /v1/ledger/verify`): recompute every `entry_hash`
from `seq`, `prev_hash` and entry content; any removal, insertion, reorder or
content change breaks the chain. Entries predating the chain (no `entry_hash`)
form a legacy prefix whose hashes are derived deterministically during
verification; each receipt's own signature still guarantees its integrity.

**Checkpoints** (`trustchain-checkpoint/1`): periodic signed commitments to the
chain head `{protocol, checkpoint_id, created_at, seq, head_hash, registry_id}`
(canonical JSON, Ed25519, base64). Publishing a checkpoint in an external
medium pins the ledger state at a point in time.

## 4. Verification endpoints

| Endpoint | Purpose |
|---|---|
| `GET /v1/attestations/{id}` | Full attestation document (this spec). |
| `GET /v1/receipts/{id}/verify` | Machine-readable signature + chain verdict for one entry. |
| `GET /v1/ledger/head` | Current chain head (`seq`, `entry_hash`). |
| `GET /v1/ledger/verify` | Full chain verification. |
| `GET /v1/ledger/checkpoints` | Signed checkpoints (newest first). |
| `GET /v1/attestations/{id}/badge.svg` | Embeddable verified-savings badge. |
| `GET /attestations/{id}` | Human verification portal (HTML). |
| `GET /registry` | Public index of opted-in attestations (HTML). |
| `POST /v1/preregistrations` | Commit audit parameters (dataset hash, delta, metric, endpoints) to the ledger **before** running the audit. Authenticated. |
| `GET /v1/preregistrations/{id}` | Fetch a preregistration commitment. Authenticated. |
| `GET /v1/preregistrations/{id}/verify/{registry_id}` | Check that a receipt entry was committed after the preregistration and matches its `dataset_sha256`/`delta`/`metric`. Authenticated. |

## 5. Notes and limitations

- Chain verification is O(n) per attestation request; acceptable at prototype
  scale. Caching/incremental verification is future work.
- The issuer public key is published per attestation and at
  `GET /v1/receipt-public-key`. Key rotation is out of scope for v1.
- `verification.*` fields are computed live at request time; they are **not**
  part of the signed commitment. The binding guarantees are the receipt
  signature (§2) and the chain (§3).
