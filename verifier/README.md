# sia-verifier

**Independent verifier for `sia-attestation/1` Proof-of-Savings attestations.**

This package lets *anyone* verify an AI cost-savings attestation **without
trusting the auditor**. It needs only the attestation document and the
issuer's public key (carried inside the document). No network calls, no
Sentinel server, no SDK.

## Why this exists

A Proof-of-Savings attestation claims: *"this AI workload was audited, the
savings are real, and here is cryptographic proof."* The whole point of the
claim is that you should not have to take the auditor's word for it. This
verifier is the reference implementation of that promise:

- **Ed25519 receipt signature** — the receipt (including `receipt_id` and the
  reproducibility manifest) is signed; any tampering breaks the signature.
- **Claim consistency** — the public claim must match the signed
  `safety_approved` field; a forged claim fails verification.
- **TrustChain hash chain** (optional) — given a ledger export, every entry is
  recomputed; removal, insertion, reorder or content tampering breaks it.
- **Checkpoints** (optional) — signed commitments pinning the chain head.

## Install

```bash
pip install sia-verifier
```

Single dependency: `cryptography`. Python 3.9+.

## CLI

```bash
# Verify an attestation document (the JSON served at GET /v1/attestations/{id})
sia-verifier attestation.json

# Also verify the hash chain from a ledger export
sia-verifier attestation.json --chain registry.jsonl

# Also verify a checkpoint signature
sia-verifier attestation.json --checkpoint checkpoint.json

# Machine-readable verdict
sia-verifier attestation.json --json
```

Exit code `0` = valid, `1` = invalid, `2` = input error — safe to wire into CI.

## Python API

```python
import json
from sia_verifier import verify_attestation, verify_chain

attestation = json.load(open("attestation.json"))
verdict = verify_attestation(attestation)

assert verdict.valid, verdict.reasons
assert verdict.receipt_signature_valid
assert verdict.claim_consistent
```

## What is NOT verified (by design)

- The `verification.*` fields inside the attestation are the *server's* live
  opinion and are deliberately ignored — they are not part of the signed
  commitment.
- The issuer's public key is taken from the document itself. For a
  higher-assurance check, pin the issuer's key out-of-band (e.g. from the
  issuer's published key registry) and compare it to `issuer.public_key`
  before trusting the verdict.
- This verifier checks cryptographic integrity, not whether the audit
  methodology was sound. Methodology is documented in the attestation's
  reproducibility manifest.

## Specification

The full format is defined by the `sia-attestation/1` specification
(commitment construction, hash chain, checkpoints). See the SIA Sentinel
repository, `docs/attestation-spec.md`.

## License

MIT
