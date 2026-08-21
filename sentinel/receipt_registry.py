"""Реестр выданных квитанций — публичный журнал TrustChain.

Хранит подписанные квитанции Proof-of-Savings в append-only JSONL. Каждая
запись включена в хеш-цепочку (поле entry_hash ссылается на prev_hash
предыдущей записи), поэтому удаление, подмена или перестановка записей
обнаруживаются проверкой цепочки, а подмена содержимого квитанции —
проверкой Ed25519-подписи публичным ключом.

Голова цепочки периодически якорится подписанными чекпоинтами
(checkpoints.jsonl): подписанный коммитмент на (seq, head_hash) можно
опубликовать во внешнем источнике, чтобы зафиксировать состояние журнала
на момент времени.

Записи, созданные до введения цепочки (без seq/prev_hash/entry_hash),
считаются legacy-префиксом: их хеши вычисляются детерминированно при
проверке, а целостность каждой квитанции по-прежнему гарантируется её
собственной подписью.

Модель записи — single-writer: журнал рассчитан на один пишущий процесс
Sentinel. Внутри процесса конкурентность закрывает threading.Lock,
между процессами — файловая блокировка на время «чтение головы +
append» (H6), поэтому несколько процессов на одном каталоге не
повредят цепочку, но горизонтальное масштабирование записи требует
БД.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import sys
import threading
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from .cryptographic_receipts import (
    CryptographicReceipt,
    ReceiptGenerator,
    ReceiptVerifier,
)

GENESIS_HASH = "0" * 64
CHECKPOINT_PROTOCOL = "trustchain-checkpoint/1"


class _FileLock:
    """Межпроцессная блокировка на отдельном lock-файле.

    Используется вокруг read-modify-append операций журнала, чтобы
    два процесса на одном каталоге не прочитали одну и ту же голову
    и не записали конфликтующие seq/prev_hash (H6).
    """

    def __init__(self, lock_path: Path):
        self._lock_path = lock_path
        self._handle: Optional[Any] = None

    def __enter__(self) -> "_FileLock":
        self._handle = open(self._lock_path, "a+")

        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(self._handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)

        return self

    def __exit__(self, *exc_info: Any) -> None:
        if self._handle is None:
            return

        try:
            if sys.platform == "win32":
                import msvcrt

                try:
                    self._handle.seek(0)
                    msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _entry_hash(seq: int, prev_hash: str, entry: dict[str, Any]) -> str:
    """Детерминированный хеш записи цепочки."""
    payload = {
        "seq": seq,
        "prev_hash": prev_hash,
        "registry_id": entry.get("registry_id"),
        "registered_at": entry.get("registered_at"),
        "receipt": entry.get("receipt"),
        "metadata": entry.get("metadata"),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


class ReceiptRegistry:
    """Append-only журнал квитанций с хеш-цепочкой и чекпоинтами."""

    def __init__(self, storage_dir: Optional[str] = None):
        self.storage_dir = Path(storage_dir or os.getenv("RECEIPTS_DIR") or "receipts")
        self.registry_file = self.storage_dir / "registry.jsonl"
        self.checkpoint_file = self.storage_dir / "checkpoints.jsonl"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._file_lock_path = self.storage_dir / ".registry.lock"

    # === Запись ===

    def register(
        self,
        receipt: CryptographicReceipt,
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """Сохраняет квитанцию в цепочку и возвращает идентификатор записи."""
        registry_id = uuid.uuid4().hex
        registered_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

        with self._lock, _FileLock(self._file_lock_path):
            head = self._head_unlocked()
            seq = head["seq"] + 1 if head else 1
            prev_hash = head["entry_hash"] if head else GENESIS_HASH

            entry = {
                "seq": seq,
                "prev_hash": prev_hash,
                "registry_id": registry_id,
                "registered_at": registered_at,
                "receipt": receipt.to_dict(),
                "metadata": metadata or {},
            }
            entry["entry_hash"] = _entry_hash(seq, prev_hash, entry)

            with open(self.registry_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str) + "\n")

        return registry_id

    def register_preregistration(self, commitment: dict[str, Any]) -> str:
        """Коммитит обязательство аудита в цепочку ДО прогона.

        Предрегистрация — запись в той же хеш-цепочке, что и квитанции:
        metadata.entry_type = "preregistration", metadata.commitment
        содержит хеши параметров (датасет, delta, метрика, конфигурации).
        Так как metadata покрыта entry_hash, обязательство
        тампер-эвидентно, а временнАя метка в цепочке доказывает, что
        оно предшествует результату аудита (seq пререгистрации <
        seq квитанции). Это закрывает p-hacking по delta и подмену
        датасета после просмотра результатов.
        """
        registry_id = uuid.uuid4().hex
        registered_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

        with self._lock, _FileLock(self._file_lock_path):
            head = self._head_unlocked()
            seq = head["seq"] + 1 if head else 1
            prev_hash = head["entry_hash"] if head else GENESIS_HASH

            entry = {
                "seq": seq,
                "prev_hash": prev_hash,
                "registry_id": registry_id,
                "registered_at": registered_at,
                "receipt": None,
                "metadata": {
                    "entry_type": "preregistration",
                    "commitment": commitment,
                },
            }
            entry["entry_hash"] = _entry_hash(seq, prev_hash, entry)

            with open(self.registry_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, default=str) + "\n")

        return registry_id

    def get_preregistration(self, registry_id: str) -> Optional[dict[str, Any]]:
        """Возвращает обязательство предрегистрации по идентификатору.

        None, если запись не найдена или не является предрегистрацией.
        """
        entry = self.get(registry_id)

        if entry is None:
            return None

        metadata = entry.get("metadata") or {}
        if metadata.get("entry_type") != "preregistration":
            return None

        return {
            "preregistration_id": registry_id,
            "registered_at": entry.get("registered_at"),
            "seq": entry.get("seq"),
            "commitment": metadata.get("commitment"),
        }

    def verify_preregistration_link(
        self,
        preregistration_id: str,
        receipt_entry: dict[str, Any],
    ) -> dict[str, Any]:
        """Проверяет, что квитанция соответствует предрегистрации.

        Сверяет обязательство (хеш датасета, delta, метрику) с фактическими
        параметрами аудита в metadata квитанции и проверяет порядок в
        цепочке: предрегистрация обязана предшествовать квитанции.
        """
        prereg = self.get_preregistration(preregistration_id)

        if prereg is None:
            return {
                "valid": False,
                "reason": f"preregistration not found: {preregistration_id}",
            }

        receipt_seq = receipt_entry.get("seq")
        if prereg["seq"] >= receipt_seq:
            return {
                "valid": False,
                "reason": "preregistration must precede the receipt in the chain",
            }

        commitment = prereg.get("commitment") or {}
        audit_meta = receipt_entry.get("metadata") or {}
        mismatches: list[str] = []

        if commitment.get("dataset_sha256") != audit_meta.get("dataset_sha256"):
            mismatches.append("dataset_sha256")
        if commitment.get("delta") != audit_meta.get("delta"):
            mismatches.append("delta")
        if commitment.get("metric") != audit_meta.get("metric"):
            mismatches.append("metric")

        if mismatches:
            return {
                "valid": False,
                "reason": f"commitment mismatch: {', '.join(mismatches)}",
            }

        return {"valid": True, "reason": None}

    # === Чтение ===

    def _load_entries(self) -> list[dict[str, Any]]:
        if not self.registry_file.exists():
            return []

        entries: list[dict[str, Any]] = []

        with open(self.registry_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()

                if not line:
                    continue

                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return entries

    def get(self, registry_id: str) -> Optional[dict[str, Any]]:
        """Возвращает полную запись по идентификатору."""
        for entry in self._load_entries():
            if entry.get("registry_id") == registry_id:
                return entry

        return None

    def list_receipts(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        """Краткие карточки квитанций, новые сверху.

        Записи предрегистрации (receipt=None) пропускаются — это не квитанции.
        """
        entries = [
            e for e in reversed(self._load_entries())
            if e.get("receipt") is not None
        ]
        window = entries[offset:offset + limit]

        summaries = []

        for entry in window:
            receipt = entry.get("receipt", {})
            summaries.append(
                {
                    "registry_id": entry.get("registry_id"),
                    "receipt_id": receipt.get("receipt_id"),
                    "registered_at": entry.get("registered_at"),
                    "evidence_id": receipt.get("evidence_id"),
                    "safety_approved": receipt.get("safety_approved"),
                    "has_manifest": receipt.get("manifest") is not None,
                    "metadata": entry.get("metadata", {}),
                }
            )

        return summaries

    def count(self) -> int:
        """Число записей в цепочке (включая предрегистрации)."""
        return len(self._load_entries())

    def count_receipts(self) -> int:
        """Число квитанций (без записей предрегистрации)."""
        return sum(1 for e in self._load_entries() if e.get("receipt") is not None)

    def list_public(
        self,
        is_published: Callable[[str], bool],
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Карточки аттестаций, чей тенант разрешил публикацию (opt-in).

        is_published(tenant_id) решает, показывать ли запись; записи без
        tenant_id в metadata считаются приватными. Новые сверху.
        Записи предрегистрации пропускаются.
        """
        published: list[dict[str, Any]] = []

        for entry in reversed(self._load_entries()):
            if entry.get("receipt") is None:
                continue

            tenant_id = (entry.get("metadata") or {}).get("tenant_id")

            if not tenant_id or not is_published(tenant_id):
                continue

            metadata = entry.get("metadata", {})
            published.append(
                {
                    "registry_id": entry.get("registry_id"),
                    "issued_at": entry.get("registered_at"),
                    "flow_name": metadata.get("flow_name"),
                    "kind": metadata.get("kind"),
                    "mode": metadata.get("mode"),
                    "savings_verified": metadata.get("savings_verified"),
                    "savings_ratio": metadata.get("savings_ratio"),
                }
            )

        return published[offset:offset + limit]

    def verify_stored(self, registry_id: str, verifier: ReceiptVerifier) -> Optional[bool]:
        """Проверяет подпись сохранённой квитанции; None — запись не найдена."""
        entry = self.get(registry_id)

        if entry is None:
            return None

        if entry.get("receipt") is None:
            # Запись предрегистрации — подписи квитанции нет
            return None

        try:
            receipt = CryptographicReceipt(**entry["receipt"])
        except Exception:
            return False

        return verifier.verify(receipt)

    # === Хеш-цепочка ===

    def _head_unlocked(self) -> Optional[dict[str, Any]]:
        entries = self._load_entries()

        if not entries:
            return None

        seq = 0
        prev_hash = GENESIS_HASH

        for entry in entries:
            seq += 1

            if entry.get("entry_hash"):
                prev_hash = entry["entry_hash"]
            else:
                # Legacy-запись: хеш вычисляется детерминированно
                prev_hash = _entry_hash(seq, prev_hash, entry)

        last = entries[-1]
        return {
            "seq": seq,
            "entry_hash": prev_hash,
            "registry_id": last.get("registry_id"),
            "registered_at": last.get("registered_at"),
        }

    def head(self) -> Optional[dict[str, Any]]:
        """Голова цепочки: seq и хеш последней записи."""
        with self._lock:
            return self._head_unlocked()

    def verify_chain(self) -> dict[str, Any]:
        """Полная проверка хеш-цепочки.

        Возвращает {valid, entries, legacy_entries, broken_at, reason}.
        """
        entries = self._load_entries()
        expected_prev = GENESIS_HASH
        legacy_entries = 0

        for position, entry in enumerate(entries, start=1):
            stored_hash = entry.get("entry_hash")

            if stored_hash:
                if entry.get("prev_hash") != expected_prev:
                    return {
                        "valid": False,
                        "entries": len(entries),
                        "legacy_entries": legacy_entries,
                        "broken_at": position,
                        "reason": "prev_hash mismatch (record removed, inserted or reordered)",
                    }

                recomputed = _entry_hash(position, expected_prev, entry)

                if recomputed != stored_hash:
                    return {
                        "valid": False,
                        "entries": len(entries),
                        "legacy_entries": legacy_entries,
                        "broken_at": position,
                        "reason": "entry_hash mismatch (record content tampered)",
                    }

                expected_prev = stored_hash
            else:
                legacy_entries += 1
                expected_prev = _entry_hash(position, expected_prev, entry)

        return {
            "valid": True,
            "entries": len(entries),
            "legacy_entries": legacy_entries,
            "broken_at": None,
            "reason": None,
        }

    # === Чекпоинты (якорение головы цепочки) ===

    def _load_checkpoints(self) -> list[dict[str, Any]]:
        if not self.checkpoint_file.exists():
            return []

        checkpoints: list[dict[str, Any]] = []

        with open(self.checkpoint_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()

                if not line:
                    continue

                try:
                    checkpoints.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return checkpoints

    def create_checkpoint(self, generator: ReceiptGenerator) -> Optional[dict[str, Any]]:
        """Подписывает текущую голову цепочки и сохраняет чекпоинт.

        Возвращает None, если журнал пуст.
        """
        with self._lock, _FileLock(self._file_lock_path):
            head = self._head_unlocked()

            if head is None:
                return None

            checkpoint = {
                "protocol": CHECKPOINT_PROTOCOL,
                "checkpoint_id": uuid.uuid4().hex,
                "created_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                "seq": head["seq"],
                "head_hash": head["entry_hash"],
                "registry_id": head["registry_id"],
                "public_key": generator.get_public_key(),
            }
            checkpoint["signature"] = generator.sign_bytes(
                _checkpoint_commitment(checkpoint)
            )

            with open(self.checkpoint_file, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(checkpoint, default=str) + "\n")

        return checkpoint

    def latest_checkpoint(self) -> Optional[dict[str, Any]]:
        checkpoints = self._load_checkpoints()
        return checkpoints[-1] if checkpoints else None

    def list_checkpoints(self, limit: int = 50) -> list[dict[str, Any]]:
        return list(reversed(self._load_checkpoints()))[:limit]

    @staticmethod
    def verify_checkpoint(checkpoint: dict[str, Any], verifier: ReceiptVerifier) -> bool:
        """Проверяет подпись чекпоинта публичным ключом."""
        signature = checkpoint.get("signature")

        if not signature:
            return False

        return verifier.verify_bytes(_checkpoint_commitment(checkpoint), signature)


def _checkpoint_commitment(checkpoint: dict[str, Any]) -> bytes:
    """Детерминированные байты, покрытые подписью чекпоинта."""
    commitment = {
        "protocol": checkpoint.get("protocol"),
        "checkpoint_id": checkpoint.get("checkpoint_id"),
        "created_at": checkpoint.get("created_at"),
        "seq": checkpoint.get("seq"),
        "head_hash": checkpoint.get("head_hash"),
        "registry_id": checkpoint.get("registry_id"),
    }
    return _canonical_json(commitment)
