from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Any, Optional

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


@dataclass
class CryptographicReceipt:
    """
    Cryptographic receipt for code verification.

    This is a simplified prototype of zkML proofs that provides:
    - Non-repudiation: cannot deny verification occurred
    - Integrity: cannot tamper with the verification result
    - Public verifiability: anyone holding the public key can verify
      the receipt without the signing secret
    - Reproducibility: the optional manifest pins the environment,
      dataset/config hashes and benchmark seeds the claim is tied to
    - Timestamp: when verification occurred
    """
    receipt_id: str
    evidence_id: str
    code_hash: str
    safety_approved: bool
    trust_level: str
    timestamp: float
    nonce: str
    signature: str
    manifest: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


def _commitment_string(receipt: CryptographicReceipt) -> bytes:
    """Deterministic serialization of the signed commitment.

    receipt_id is part of the signed commitment (H1) so a signature
    cannot be lifted off one receipt and replayed against a different
    receipt_id.
    """
    commitment: dict[str, Any] = {
        "receipt_id": receipt.receipt_id,
        "evidence_id": receipt.evidence_id,
        "code_hash": receipt.code_hash,
        "safety_approved": receipt.safety_approved,
        "trust_level": receipt.trust_level,
        "timestamp": receipt.timestamp,
        "nonce": receipt.nonce,
    }

    if receipt.manifest is not None:
        commitment["manifest"] = receipt.manifest

    return json.dumps(commitment, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _derive_private_key(material: str) -> Ed25519PrivateKey:
    """Deterministically derive an Ed25519 key pair from seed material."""
    seed = hashlib.sha256(material.encode('utf-8')).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _load_public_key(value: str) -> Ed25519PublicKey:
    """Load a base64 raw 32-byte Ed25519 public key.

    Strictly rejects anything that is not a valid raw public key (H2).
    The previous fallback silently derived a key pair from arbitrary
    seed material, so a signing secret passed in place of a public key
    was accepted instead of failing loudly.
    """
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(
            "public_key must be a base64-encoded raw 32-byte Ed25519 public key"
        ) from exc

    if len(raw) != 32:
        raise ValueError(
            f"public_key must decode to exactly 32 bytes, got {len(raw)}"
        )

    return Ed25519PublicKey.from_public_bytes(raw)


class ReceiptGenerator:
    """
    Generates cryptographic receipts for code verifications.

    Signs each receipt with an Ed25519 private key and publishes the
    corresponding public key, so any third party can verify receipts
    without ever holding the signing secret. The seed material can be
    provided explicitly or via the RECEIPT_SIGNING_KEY environment
    variable; without either, an ephemeral key is generated.
    In production, this would be replaced with zk-SNARKs/zk-STARKs.
    """

    def __init__(self, signing_key: Optional[str] = None):
        """
        Initialize receipt generator.

        Args:
            signing_key: Seed material for the Ed25519 signing key.
                         Falls back to RECEIPT_SIGNING_KEY, then to an
                         ephemeral random key.
        """
        if signing_key is None:
            signing_key = os.getenv("RECEIPT_SIGNING_KEY") or secrets.token_hex(32)

        self._private_key = _derive_private_key(signing_key)

    def get_public_key(self) -> str:
        """Return the base64 raw public key matching the signing key."""
        raw = self._private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode('ascii')

    def _compute_hash(self, data: str) -> str:
        """Compute SHA256 hash."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _sign(self, data: bytes) -> str:
        """Sign data with Ed25519, return base64 signature."""
        signature = self._private_key.sign(data)
        return base64.b64encode(signature).decode('ascii')

    def generate_receipt(
        self,
        evidence_id: str,
        code: str,
        safety_approved: bool,
        trust_level: str,
        manifest: Optional[dict[str, Any]] = None,
    ) -> CryptographicReceipt:
        """
        Generate cryptographic receipt for verification.

        Args:
            evidence_id: ID of evidence record
            code: Code that was verified
            safety_approved: Whether safety check passed
            trust_level: Agent trust level
            manifest: Optional reproducibility manifest (environment,
                      dataset/config hashes, seeds, pricing) that gets
                    covered by the signature

        Returns:
            CryptographicReceipt with signature
        """
        receipt_id = self._compute_hash(f"{evidence_id}{time.time()}")
        code_hash = self._compute_hash(code)
        timestamp = time.time()
        nonce = self._compute_hash(f"{timestamp}{receipt_id}")

        receipt = CryptographicReceipt(
            receipt_id=receipt_id,
            evidence_id=evidence_id,
            code_hash=code_hash,
            safety_approved=safety_approved,
            trust_level=trust_level,
            timestamp=timestamp,
            nonce=nonce,
            signature="",
            manifest=manifest,
        )

        receipt.signature = self._sign(_commitment_string(receipt))

        return receipt

    def verify_receipt(self, receipt: CryptographicReceipt) -> bool:
        """
        Verify a receipt with the generator's own key pair.

        Args:
            receipt: Receipt to verify

        Returns:
            True if receipt is valid
        """
        try:
            self._private_key.public_key().verify(
                base64.b64decode(receipt.signature),
                _commitment_string(receipt),
            )
            return True
        except (InvalidSignature, ValueError):
            return False

    def verify_receipt_json(self, receipt_json: str) -> bool:
        """
        Verify receipt from JSON string.

        Args:
            receipt_json: JSON string of receipt

        Returns:
            True if receipt is valid
        """
        try:
            receipt_dict = json.loads(receipt_json)
            receipt = CryptographicReceipt(**receipt_dict)
            return self.verify_receipt(receipt)
        except Exception:
            return False

    def sign_bytes(self, data: bytes) -> str:
        """Sign arbitrary bytes with Ed25519, return base64 signature.

        Used to anchor ledger checkpoints (signed commitments to the
        current head hash of the receipt chain).
        """
        return self._sign(data)


class ReceiptVerifier:
    """
    Public verifier for receipts (needs only the public key).

    Verification is a deterministic Ed25519 signature check: anyone can
    verify a receipt knowing just the published public key, without
    access to the signing secret.
    """

    def __init__(self, public_key: str):
        """
        Initialize public verifier.

        Args:
            public_key: Base64 raw 32-byte Ed25519 public key.
                        Anything else raises ValueError — seed material
                        is never accepted here (H2).
        """
        self._public_key = _load_public_key(public_key)

    def verify(self, receipt: CryptographicReceipt) -> bool:
        """Verify receipt using the public key."""
        try:
            signature = base64.b64decode(receipt.signature, validate=True)
        except Exception:
            return False

        try:
            self._public_key.verify(signature, _commitment_string(receipt))
            return True
        except (InvalidSignature, ValueError):
            return False

    def verify_json(self, receipt_json: str) -> bool:
        """Verify receipt from JSON."""
        try:
            receipt_dict = json.loads(receipt_json)
            receipt = CryptographicReceipt(**receipt_dict)
            return self.verify(receipt)
        except Exception:
            return False

    def verify_bytes(self, data: bytes, signature_b64: str) -> bool:
        """Verify a base64 Ed25519 signature over arbitrary bytes.

        Counterpart of ReceiptGenerator.sign_bytes — used to verify
        ledger checkpoint anchors with only the public key.
        """
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except Exception:
            return False

        try:
            self._public_key.verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False
