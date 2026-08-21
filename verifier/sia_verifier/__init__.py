"""sia-verifier — независимый верификатор аттестаций Proof-of-Savings.

Минимальный пакет (только `cryptography` + stdlib), который проверяет
аттестации стандарта ``sia-attestation/1`` **без доверия к аудитору**:
нужен только сам документ аттестации и (опционально) выгрузка журнала
TrustChain. Никаких сетевых вызовов, никакого SDK Sentinel.

Что проверяется:

1. **Подпись квитанции** — Ed25519 (RFC 8032) над каноническим JSON
   коммитмента, восстановленного из полей квитанции (включая
   ``receipt_id``). Публичный ключ берётся из ``issuer.public_key``
   аттестации и принимается только в виде base64 raw 32 байт.
2. **Согласованность заявления** — ``receipt.safety_approved`` должен
   совпадать с ``claim.savings_verified``: подпись покрывает именно
   ``safety_approved``, поэтому расхождение означает подделку заявления.
3. **Хеш-цепочка TrustChain** (опционально, по выгрузке журнала) —
   каждая запись пересчитывается из ``seq``, ``prev_hash`` и содержимого;
   удаление, вставка, перестановка или подмена записи ломают цепочку.
4. **Чекпоинты** — подписанные коммитменты на голову цепочки (v1) и на
   голову цепочки + Merkle tree head (v2).
5. **Merkle-доказательства** (RFC 6962) — ``verify_inclusion`` проверяет
   включение записи в tree head, ``verify_consistency`` — что дерево
   размера N является продолжением дерева размера M.

CLI::

    python -m sia_verifier attestation.json
    python -m sia_verifier attestation.json --chain registry.jsonl

Программа и API возвращают вердикт; ненулевой код выхода при
невалидной аттестации позволяет встраивать проверку в CI.
"""
from __future__ import annotations

from .core import (
    ATTESTATION_SPEC,
    AttestationVerdict,
    ChainVerdict,
    leaf_hash,
    resolve_receipt_key,
    verify_attestation,
    verify_chain,
    verify_checkpoint,
    verify_consistency,
    verify_inclusion,
    verify_key_declarations,
    verify_receipt,
)

__version__ = "1.1.0"

__all__ = [
    "ATTESTATION_SPEC",
    "AttestationVerdict",
    "ChainVerdict",
    "leaf_hash",
    "resolve_receipt_key",
    "verify_attestation",
    "verify_chain",
    "verify_checkpoint",
    "verify_consistency",
    "verify_inclusion",
    "verify_key_declarations",
    "verify_receipt",
    "__version__",
]
