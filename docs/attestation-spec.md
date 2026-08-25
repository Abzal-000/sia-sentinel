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
| `non_inferior` | bool | Non-inferiority verdict: CI lower bound for `p_new − p_old` > `−delta` **and** MDD ≤ delta (the run could statistically have detected a delta-sized drop; zero discordance `b = c = 0` is exempt — the observed difference is exactly 0 and the published MDD carries the honesty). A verdict the gate blocks is reported as `inconclusive`, not `inferior`. |
| `delta` | number | Pre-declared non-inferiority margin (0 = no quality drop tolerated; default for deterministic code suites). |
| `mcnemar_p` | number | Exact McNemar two-sided p-value on discordant pairs. |
| `minimum_detectable_difference` | number | MDD at n pairs, α = (1−confidence)/2, 80% power: the smallest quality drop this audit could have noticed. The verdict reads the lower bound of the two-sided confidence interval — a one-sided test at that α — so the MDD is computed for the same test that carries it (an earlier version used α = 1−confidence and overstated sensitivity). Computed from `max(assumed, observed)` discordance — the observed rate `((b+c)/n)` is a floor-raiser, so the published MDD can never understate this run's blindness when discordance exceeds the 10% planning assumption. |
| `n_pairs` | integer | Number of paired observations. |
| `b_old_pass_new_fail` | integer | Discordant pairs where old passed and new failed. |
| `c_old_fail_new_pass` | integer | Discordant pairs where old failed and new passed. |
| `ci_lower`, `ci_upper` | number | MOVER-style interval for `p_new − p_old`: quadratic combination of Wilson bounds on the discordant cells (no correlation correction; not Newcombe 2006, whose ψ-adjusted marginal construction calibrated worse on our n). |
| `declared_limits` | string \| null | Budget limits frozen at preregistration, published next to the MDD so sensitivity is not mistaken for a chosen statistic: repetitions per item (R), dataset size (n), and a note that the MDD is what this budget can detect (80% power) — not a quality statement. |

`savings_verified` requires quality preservation — `non_inferior = true`, or
zero discordance (`b = c = 0`, observed quality identical; the claim remains
honest given the published MDD) — **and** positive savings.

**What actually served.** The signed manifest records, per side, the model
identifiers and build fingerprints (`system_fingerprint`) returned by the
endpoint during the run (missing fields are published as absent), together
with the **fingerprint coverage** — how many of the side's calls reported a
fingerprint out of how many ran. A single value in a set proves nothing on
its own: a run where 3 of 450 calls reported a fingerprint publishes the
same list as one where all 450 did. The requested model name alone does not
protect against a silent provider-side swap of the served build mid-run —
which would quietly break pairing; the fingerprints plus their coverage
make it visible.

**Who picked the candidate.** The manifest carries `candidate_selected_by`
(`user` | `optimizer`). An auditor certifying a configuration its own
optimizer selected has a conflict of interest; publishing who chose the
candidate answers that objection without hiding it in the pipeline.

### 1.2 Preregistration (`claim.preregistration`)

For `llm_flow`/`optimize` flows the audit parameters are committed to the
ledger **before** the run (`POST /v1/preregistrations`, protocol
`sia-preregistration/4`), clinical-trial style: no post-hoc dataset swaps or
delta shopping. The attestation carries the commitment it was checked
against:

| Field | Type | Description |
|---|---|---|
| `dataset_sha256` | string | SHA-256 of the dataset (`prompt\|expect_contains` lines). |
| `delta` | number | The non-inferiority margin declared pre-run. |
| `metric` | string | Quality metric. `"expect_contains"`: expected substring anywhere in the response. `"expect_contains/digit-anchored"` (beacon): the expected `ANSWER=<n>` string must be the LAST non-empty line of the response — mentioning it mid-reasoning does not count. |
| `repetitions` | integer | Trials per dataset item (R); an item passes only if all R trials pass. |
| `replay_tolerance` | number | Pre-declared share of dataset items an independent re-player may see answered differently from the recorded run (0–1). The served endpoint is not deterministic over time even at temperature 0 — measured element drift 1–4 of 90 per model between identical runs. Without this pre-registered disclosure an honest verifier looks like a forger, and real forgery hides inside the tolerance. Default 0.05. |
| `replay_tolerance_rule` | string | How the tolerance is accounted (`directional-one-sided:toward-claim` since `sia-preregistration/3`): divergences are counted separately by direction — those shifting the outcome **toward** the attested claim (new passes where the run recorded a failure, or old fails where it recorded a pass) and those shifting away — and the threshold applies to the one-sided toward-claim share. Honest drift is roughly symmetric; forgery pushes only one way, so a one-sided threshold rejects directional tampering about twice as hard at the same number while costing honest re-players nothing. |
| `anchor_declaration` | string \| null | The operator's explicit statement of external-anchoring status made **at registration time** (`external-anchor`, `unanchored`, …). Preregistration **refuses** to run without it: "no anchor — no record" lives in code, not in an operator's memory, so an unanchored entry can only exist by conscious, permanently visible declaration. |

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
| `kid` | string \| null | Key identifier of the signing key (`SHA256(raw public key)[:16]` hex) — see §3.2. Present on receipts issued after key rotation was introduced; **covered by the signature when present**. |

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
  "manifest": { ... },  // included only when manifest is not null
  "kid": "0123456789abcdef"  // included only when kid is not null
}
```

`receipt_id` is part of the commitment so a signature cannot be lifted off
one receipt and replayed against a different `receipt_id`. `kid` is included
whenever the receipt carries one, binding the signature to the exact key that
produced it — omit it from the commitment only for receipts without `kid`
(legacy pre-rotation receipts).

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

**Incremental verification**: `verify_chain()` caches the last verified
position (seq + hash, in memory per process) and re-checks only new entries,
plus an anchor check that the cached boundary entry still matches the cached
hash — a rewritten prefix invalidates the cache and forces full re-verification.
`GET /v1/ledger/verify?full=true` always verifies from genesis.

**Checkpoints** (`trustchain-checkpoint/2`): periodic signed commitments to the
chain head AND the Merkle tree head
`{protocol, checkpoint_id, created_at, seq, head_hash, registry_id, tree_size, root_hash, kid}`
(canonical JSON, Ed25519, base64). `kid` identifies the signing key (§3.2);
legacy `trustchain-checkpoint/1` checkpoints (no tree head) remain verifiable.

### 3.1 Merkle accumulator (RFC 6962-style)

Every entry's `entry_hash` (legacy entries: derived hash) is a leaf of a Merkle
tree over the ledger, in `seq` order. Hashing follows RFC 6962 §2.1 with
domain separation:

- leaf: `SHA256(0x00 || entry_hash)`
- node: `SHA256(0x01 || left || right)`

The **tree head** `{tree_size, root_hash}` covers every entry, so proofs
against it bind individual receipts to the whole ledger state:

- **Inclusion proof** (`GET /v1/ledger/inclusion/{registry_id}`): audit path
  (list of `{hash, direction}` from leaf to root). Verified by folding:
  start from `leaf_hash(entry_hash)`, combine `H(0x01 || sibling || fn)` for
  `direction=left` (sibling on the left) or `H(0x01 || fn || sibling)` for
  `direction=right`; the result must equal `root_hash` for the given
  `tree_size`.
- **Consistency proof** (`GET /v1/ledger/consistency?from=&to=`): RFC 6962
  SUBPROOF proving that the tree of size `to` is an append-only extension of
  the tree of size `from`. Verified by reconstructing BOTH roots from the
  proof and comparing with the two known heads.

Both proofs are verified by the standalone `sia-verifier` package
(`verify_inclusion`, `verify_consistency`) — no trust in the auditor required.

### 3.2 Key rotation (`kid`)

Receipts and checkpoints carry a `kid` — a deterministic short fingerprint of
the signing key (`SHA256(raw public key)[:16]` hex). `kid` is part of the
signed commitment, so a signature is bound to a specific key.

Key declarations are entries in the chain itself (`metadata.entry_type="key"`):
`{kid, public_key, purpose, declared_at}` signed (Ed25519 over canonical JSON)
by the key that was **active at declaration time** (`signer_kid`):

- the genesis declaration is self-signed (the bootstrap key declares itself);
- rotation declares the NEW key in a record signed by the OLD key, keeping an
  unbroken chain of trust from the genesis key to the current one.

A verifier reconstructs the `kid → public_key` table from the chain
(`sia_verifier.verify_key_declarations`) and verifies any receipt or checkpoint
against the key its `kid` names — receipts issued before a rotation stay
verifiable after it. Rotation procedure: `POST /v1/ledger/keys/rotate`
(platform admin) declares the new key and switches the active generator;
persist the returned seed as the new `RECEIPT_SIGNING_KEY`.

### 3.3 External checkpoint anchoring

A checkpoint stored next to the ledger does not protect against an attacker
who controls the server. Anchoring (`POST /v1/ledger/anchor`, admin;
`scripts/anchor_checkpoint.py` for cron) publishes the signed checkpoint to
external storage the auditor cannot rewrite:

- **file transport**: `anchors/<checkpoint_id>.json` (`ANCHORS_DIR`), staged
  for sync to immutable external storage (S3 with object lock / WORM bucket,
  a public git remote, a gist feed);
- **HTTP transport**: POST to `ANCHOR_URL` (e.g. a timestamping or
  WORM-ingest service; SSRF-guarded — internal addresses are rejected).

An auditor compares the externally anchored `{seq, head_hash, tree_size,
root_hash}` with the live chain head: if the live head does not extend the
anchor (consistency proof, §3.1), history was rewritten after the anchor.

## 4. Verification endpoints

| Endpoint | Purpose |
|---|---|
| `GET /v1/attestations/{id}` | Full attestation document (this spec). |
| `GET /v1/receipts/{id}/verify` | Machine-readable signature + chain verdict for one entry. |
| `GET /v1/ledger/head` | Current chain head + Merkle tree head (`seq`, `entry_hash`, `tree_size`, `root_hash`). |
| `GET /v1/ledger/verify` | Chain verification (incremental by default; `?full=true` from genesis). |
| `GET /v1/ledger/inclusion/{registry_id}` | Merkle inclusion proof for an entry (§3.1). |
| `GET /v1/ledger/consistency?from=&to=` | Merkle consistency proof between two tree heads (§3.1). |
| `GET /v1/ledger/checkpoints` | Signed checkpoints (newest first). |
| `GET /v1/ledger/keys` | Key declarations from the chain (§3.2). |
| `GET /v1/attestations/{id}/badge.svg` | Embeddable verified-savings badge. |
| `GET /attestations/{id}` | Human verification portal (HTML). |
| `GET /registry` | Public index of opted-in attestations (HTML). |
| `POST /v1/preregistrations` | Commit audit parameters (dataset hash, delta, metric, endpoints) to the ledger **before** running the audit. Authenticated. |
| `GET /v1/preregistrations/{id}` | Fetch a preregistration commitment. Authenticated. |
| `GET /v1/preregistrations/{id}/verify/{registry_id}` | Check that a receipt entry was committed after the preregistration and matches its `dataset_sha256`/`delta`/`metric`. Authenticated. |

Admin-only ledger operations: `POST /v1/ledger/checkpoint` (sign a
checkpoint), `POST /v1/ledger/anchor` (checkpoint + external publication,
§3.3), `POST /v1/ledger/keys/rotate` (key rotation, §3.2).

## 5. Notes and limitations

- Incremental chain verification trusts the prefix verified earlier in the
  same process; `?full=true` re-verifies from genesis. Run a full
  verification (and compare against an external anchor, §3.3) periodically
  or when tampering is suspected.
- The HTTP anchor transport posts the checkpoint but does not verify what
  the remote endpoint stored; the guarantee comes from the external medium's
  immutability (WORM/lock policy), not from the POST itself.
- The Merkle accumulator is rebuilt from the journal on demand (O(n) read);
  acceptable at prototype scale.
- `verification.*` fields are computed live at request time; they are **not**
  part of the signed commitment. The binding guarantees are the receipt
  signature (§2), the chain + Merkle proofs (§3.1) and the key chain (§3.2).
