from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass, asdict
from typing import Any, Optional

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from sia.config import resolve_env


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
    # C3: идентификатор ключа, которым подписана квитанция. None для
    # квитанций, выпущенных до введения ротации ключей.
    kid: Optional[str] = None

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

    C3: ``kid`` входит в коммитмент, когда задан, — подпись привязана к
    конкретному ключу. Legacy-квитанции без kid сериализуются как раньше.
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

    if receipt.kid is not None:
        commitment["kid"] = receipt.kid

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
    variable (or .env — resolved like every other project secret).
    In production, this would be replaced with zk-SNARKs/zk-STARKs.
    """

    def __init__(
        self,
        signing_key: Optional[str] = None,
        allow_ephemeral: bool = False,
    ):
        """
        Initialize receipt generator.

        Args:
            signing_key: Seed material for the Ed25519 signing key.
                         Falls back to RECEIPT_SIGNING_KEY (env, then .env).
            allow_ephemeral: Разрешить эфемерный ключ, когда материал не
                         задан нигде. По умолчанию ЗАПРЕЩЁН: квитанции,
                         подписанные эфемерным ключом, невозможно привязать
                         к SIA после рестарта — это молча необратимая
                         потеря. Явное разрешение оставлено только dev-старту
                         API, который сам печатает громкое предупреждение.

        Raises:
            ValueError: если материал не задан и allow_ephemeral=False.
        """
        if signing_key is None:
            signing_key = resolve_env("RECEIPT_SIGNING_KEY")

        if signing_key is None:
            if not allow_ephemeral:
                raise ValueError(
                    "RECEIPT_SIGNING_KEY is not set (env or .env). Receipts "
                    "signed with an ephemeral key cannot be verified after a "
                    "restart. Set RECEIPT_SIGNING_KEY, or pass an explicit "
                    "signing_key, or opt into allow_ephemeral=True explicitly."
                )
            signing_key = secrets.token_hex(32)

        self._private_key = _derive_private_key(signing_key)

    @property
    def kid(self) -> str:
        """C3: идентификатор ключа — короткий отпечаток публичного ключа.

        kid = первые 16 hex-символов SHA256(raw публичного ключа).
        Детерминирован: один и тот же ключ всегда даёт один kid, поэтому
        декларации ключей в цепочке и квитанции согласованы без внешнего
        реестра.
        """
        raw = self._private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        return hashlib.sha256(raw).hexdigest()[:16]

    def get_public_key(self) -> str:
        """Return the base64 raw public key matching the signing key."""
        raw = self._private_key.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode('ascii')

    def sign_ph_digest(self, digest64: bytes) -> bytes:
        """Ed25519ph (RFC 8032 HashEdDSA) над ГОТОВЫМ прехешем PH(M).

        Для Rekor hashedrekord: инстанс трактует декодированное
        spec.data.hash.value как PH(M) и верифицирует с WithED25519ph —
        ровно ОДИН хеш, никаких до-хешей сообщения. pyca ph-API не имеет,
        поэтому арифметика RFC 8032 §6 локальная (sentinel.ed25519ph,
        самотест из вектора §7.3 + перекрёстные проверки с pyca). Seed —
        тот же детерминированный, что у обычных квитанций: подписант
        остаётся receipt-key.

        Ограничение: скалярное умножение в ed25519ph НЕ защищено от атак
        по времени (см. оговорку в его докстринге) — приемлемо для
        офлайн/крон-анкоринга на собственной машине.
        """
        from .ed25519ph import sign_digest

        seed = self._private_key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption(),
        )
        return sign_digest(seed, digest64)

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
            kid=self.kid,
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


class KeyringVerifier:
    """C3: верификатор, знающий несколько ключей по kid.

    После ротации ключа старые квитанции подписаны старым ключом, новые —
    новым. KeyringVerifier держит таблицу kid → публичный ключ и выбирает
    ключ по ``receipt.kid``; для legacy-квитанций без kid используется
    fallback-ключ (текущий на момент до ротации).
    """

    def __init__(self, fallback_public_key: Optional[str] = None):
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fallback: Optional[Ed25519PublicKey] = (
            _load_public_key(fallback_public_key) if fallback_public_key else None
        )

    def add_key(self, kid: str, public_key_b64: str) -> None:
        """Регистрирует публичный ключ под kid (невалидный — ValueError)."""
        self._keys[kid] = _load_public_key(public_key_b64)

    def set_fallback(self, public_key_b64: str) -> None:
        self._fallback = _load_public_key(public_key_b64)

    def _key_for(self, receipt: CryptographicReceipt) -> Optional[Ed25519PublicKey]:
        if receipt.kid is not None:
            return self._keys.get(receipt.kid)

        return self._fallback

    def verify(self, receipt: CryptographicReceipt) -> bool:
        """Проверяет квитанцию ключом, соответствующим её kid."""
        public_key = self._key_for(receipt)

        if public_key is None:
            return False

        try:
            signature = base64.b64decode(receipt.signature, validate=True)
        except Exception:
            return False

        try:
            public_key.verify(signature, _commitment_string(receipt))
            return True
        except (InvalidSignature, ValueError):
            return False
