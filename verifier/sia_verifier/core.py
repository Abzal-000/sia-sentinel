"""Ядро независимой верификации стандарта ``sia-attestation/1``.

Реализация намеренно автономна: она повторяет правила построения
коммитментов и хеш-цепочки из спецификации, а не импортирует код
Sentinel, чтобы третья сторона могла проверить аттестацию, не доверяя
аудитору и не запуская его сервер.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ATTESTATION_SPEC = "sia-attestation/1"
GENESIS_HASH = "0" * 64
CHECKPOINT_PROTOCOL = "trustchain-checkpoint/1"


def _canonical_json(value: dict[str, Any]) -> bytes:
    """Каноническая сериализация коммитмента (spec §2.1)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _load_public_key(value: str) -> Ed25519PublicKey:
    """Строгая загрузка публичного ключа: только base64 raw 32 байта.

    Сид-материал и любые другие форматы отклоняются — иначе секрет
    подписи, переданный вместо публичного ключа, был бы молча принят.
    """
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(
            "issuer.public_key must be a base64-encoded raw 32-byte Ed25519 public key"
        ) from exc

    if len(raw) != 32:
        raise ValueError(f"issuer.public_key must decode to exactly 32 bytes, got {len(raw)}")

    return Ed25519PublicKey.from_public_bytes(raw)


def _receipt_commitment(receipt: dict[str, Any]) -> bytes:
    """Коммитмент квитанции, покрытый подписью (spec §2.1).

    ``receipt_id`` входит в коммитмент: подпись нельзя перенести с одной
    квитанции на другую.
    """
    commitment: dict[str, Any] = {
        "receipt_id": receipt.get("receipt_id"),
        "evidence_id": receipt.get("evidence_id"),
        "code_hash": receipt.get("code_hash"),
        "safety_approved": receipt.get("safety_approved"),
        "trust_level": receipt.get("trust_level"),
        "timestamp": receipt.get("timestamp"),
        "nonce": receipt.get("nonce"),
    }

    if receipt.get("manifest") is not None:
        commitment["manifest"] = receipt["manifest"]

    return _canonical_json(commitment)


def verify_receipt(receipt: dict[str, Any], public_key_b64: str) -> bool:
    """Проверяет Ed25519-подпись квитанции публичным ключом.

    Возвращает True только при валидной подписи; любые ошибки формата
    дают False (вердикт, а не исключение).
    """
    try:
        public_key = _load_public_key(public_key_b64)
        signature = base64.b64decode(receipt.get("signature", ""), validate=True)
        public_key.verify(signature, _receipt_commitment(receipt))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


@dataclass
class AttestationVerdict:
    """Результат независимой проверки аттестации."""

    valid: bool
    receipt_signature_valid: bool
    claim_consistent: bool
    spec_recognized: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "receipt_signature_valid": self.receipt_signature_valid,
            "claim_consistent": self.claim_consistent,
            "spec_recognized": self.spec_recognized,
            "reasons": list(self.reasons),
        }


def verify_attestation(attestation: dict[str, Any]) -> AttestationVerdict:
    """Независимая проверка аттестационного документа.

    Проверяет подпись квитанции публичным ключом из самого документа и
    согласованность заявления с подписанным полем ``safety_approved``.
    Поля ``verification.*`` сервера намеренно игнорируются — они не
    входят в подписанный коммитмент и не являются доказательством.
    """
    reasons: list[str] = []

    spec = attestation.get("spec")
    spec_recognized = spec == ATTESTATION_SPEC
    if not spec_recognized:
        reasons.append(f"unrecognized spec: {spec!r} (expected {ATTESTATION_SPEC!r})")

    receipt = attestation.get("receipt")
    if not isinstance(receipt, dict):
        reasons.append("missing or malformed receipt")
        return AttestationVerdict(
            valid=False,
            receipt_signature_valid=False,
            claim_consistent=False,
            spec_recognized=spec_recognized,
            reasons=reasons,
        )

    issuer = attestation.get("issuer") or {}
    public_key_b64 = issuer.get("public_key", "")

    signature_valid = verify_receipt(receipt, public_key_b64)
    if not signature_valid:
        reasons.append("receipt signature invalid for issuer.public_key")

    claim = attestation.get("claim") or {}
    claim_consistent = receipt.get("safety_approved") == claim.get("savings_verified")
    if not claim_consistent:
        reasons.append(
            "claim.savings_verified does not match signed receipt.safety_approved"
        )

    valid = signature_valid and claim_consistent and spec_recognized

    return AttestationVerdict(
        valid=valid,
        receipt_signature_valid=signature_valid,
        claim_consistent=claim_consistent,
        spec_recognized=spec_recognized,
        reasons=reasons,
    )


def _entry_hash(seq: int, prev_hash: str, entry: dict[str, Any]) -> str:
    """Детерминированный хеш записи цепочки (spec §3)."""
    payload = {
        "seq": seq,
        "prev_hash": prev_hash,
        "registry_id": entry.get("registry_id"),
        "registered_at": entry.get("registered_at"),
        "receipt": entry.get("receipt"),
        "metadata": entry.get("metadata"),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass
class ChainVerdict:
    """Результат проверки хеш-цепочки TrustChain."""

    valid: bool
    entries: int
    legacy_entries: int
    broken_at: Optional[int]
    reason: Optional[str]
    contains_attestation: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "entries": self.entries,
            "legacy_entries": self.legacy_entries,
            "broken_at": self.broken_at,
            "reason": self.reason,
            "contains_attestation": self.contains_attestation,
        }


def verify_chain(
    entries: list[dict[str, Any]],
    attestation_id: Optional[str] = None,
) -> ChainVerdict:
    """Проверяет выгрузку журнала TrustChain (append-only JSONL).

    ``entries`` — список записей в порядке журнала. Если задан
    ``attestation_id``, дополнительно проверяется, что запись с таким
    ``registry_id`` присутствует в цепочке.
    """
    expected_prev = GENESIS_HASH
    legacy_entries = 0
    found = attestation_id is None

    for position, entry in enumerate(entries, start=1):
        if attestation_id is not None and entry.get("registry_id") == attestation_id:
            found = True

        stored_hash = entry.get("entry_hash")

        if stored_hash:
            if entry.get("prev_hash") != expected_prev:
                return ChainVerdict(
                    valid=False,
                    entries=len(entries),
                    legacy_entries=legacy_entries,
                    broken_at=position,
                    reason="prev_hash mismatch (record removed, inserted or reordered)",
                    contains_attestation=found if found else None,
                )

            recomputed = _entry_hash(position, expected_prev, entry)

            if recomputed != stored_hash:
                return ChainVerdict(
                    valid=False,
                    entries=len(entries),
                    legacy_entries=legacy_entries,
                    broken_at=position,
                    reason="entry_hash mismatch (record content tampered)",
                    contains_attestation=found if found else None,
                )

            expected_prev = stored_hash
        else:
            legacy_entries += 1
            expected_prev = _entry_hash(position, expected_prev, entry)

    return ChainVerdict(
        valid=True,
        entries=len(entries),
        legacy_entries=legacy_entries,
        broken_at=None,
        reason=None,
        contains_attestation=found,
    )


def _checkpoint_commitment(checkpoint: dict[str, Any]) -> bytes:
    """Детерминированные байты, покрытые подписью чекпоинта (spec §3)."""
    commitment = {
        "protocol": checkpoint.get("protocol"),
        "checkpoint_id": checkpoint.get("checkpoint_id"),
        "created_at": checkpoint.get("created_at"),
        "seq": checkpoint.get("seq"),
        "head_hash": checkpoint.get("head_hash"),
        "registry_id": checkpoint.get("registry_id"),
    }
    return _canonical_json(commitment)


def verify_checkpoint(checkpoint: dict[str, Any], public_key_b64: str) -> bool:
    """Проверяет подпись чекпоинта публичным ключом."""
    signature = checkpoint.get("signature")

    if not signature or checkpoint.get("protocol") != CHECKPOINT_PROTOCOL:
        return False

    try:
        public_key = _load_public_key(public_key_b64)
        public_key.verify(base64.b64decode(signature, validate=True), _checkpoint_commitment(checkpoint))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
