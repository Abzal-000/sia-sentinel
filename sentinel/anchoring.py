"""Внешний анкоринг чекпоинтов TrustChain (C4).

Подписанный чекпоинт фиксирует состояние леджера на момент времени, но
если хранить его только рядом с самим леджером, компрометация сервера
позволяет переписать и то, и другое. Анкоринг публикует чекпоинт во
ВНЕШНЕЕ хранилище, которое злоумышленник, контролирующий Sentinel,
изменить не может:

- файловый транспорт — каталог ``anchors/`` (синхронизация наружу:
  rsync/S3/git-remote настраивается отдельно, см. docs/attestation-spec.md §6);
- HTTP-транспорт — POST подписанного чекпоинта на ``ANCHOR_URL``
  (например, публичный gist-прокси, bucket с WORM-политикой,
  сторонний timestamping-сервис);
- Rekor (Sigstore) — hashedrekord в ПУБЛИЧНОМ append-only логе: включение
  записи доказывается против Merkle-дерева, подписанного ключами Sigstore,
  то есть проверяющий получает свидетеля вне нашей инфраструктуры, а не
  «поверьте нашему таймстемпу». Включается явно (REKOR_ANCHOR=1); для
  записи №1 якорь обязан сработать В МОМЕНТ создания — дописанный потом
  доказывает меньше.

Сравнивая внешний анкор с текущей головой цепочки, любой аудитор
доказуемо фиксирует, что история не переписывалась с момента анкора.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional, Protocol

from .atomic_write import atomic_write_json
from .outbound_webhooks import validate_webhook_url

logger = logging.getLogger(__name__)


class AnchorTransport(Protocol):
    """Интерфейс транспорта анкоринга."""

    name: str

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        """Публикует чекпоинт; возвращает {ok, detail} (не бросает)."""
        ...


class FileAnchorTransport:
    """Пишет чекпоинт в локальный каталог анкоров.

    Каталог предназначен для синхронизации наружу (cron + rsync/S3).
    Файл называется по ``checkpoint_id`` и не перезаписывается.
    """

    name = "file"

    def __init__(self, anchors_dir: Optional[str] = None):
        self.anchors_dir = Path(
            anchors_dir or os.getenv("ANCHORS_DIR") or "anchors"
        )

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        checkpoint_id = checkpoint.get("checkpoint_id")

        if not checkpoint_id:
            return {"ok": False, "detail": "checkpoint has no checkpoint_id"}

        try:
            self.anchors_dir.mkdir(parents=True, exist_ok=True)
            path = self.anchors_dir / f"{checkpoint_id}.json"

            if path.exists():
                return {"ok": True, "detail": f"already anchored: {path}"}

            atomic_write_json(path, checkpoint)
            return {"ok": True, "detail": str(path)}
        except OSError as exc:
            logger.error("File anchor failed: %s", exc)
            return {"ok": False, "detail": str(exc)}


class HttpAnchorTransport:
    """POST-ит подписанный чекпоинт на внешний URL (ANCHOR_URL).

    URL проходит ту же SSRF-проверку, что и вебхуки: внутренние адреса
    (metadata, loopback, private) отклоняются.
    """

    name = "http"

    def __init__(self, url: Optional[str] = None, timeout: float = 10.0):
        self.url = url or os.getenv("ANCHOR_URL") or ""
        self.timeout = timeout

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        if not self.url:
            return {"ok": False, "detail": "ANCHOR_URL is not configured"}

        try:
            validate_webhook_url(self.url)
        except ValueError as exc:
            logger.error("HTTP anchor URL rejected (SSRF guard): %s", exc)
            return {"ok": False, "detail": f"rejected: {exc}"}

        try:
            import httpx

            response = httpx.post(
                self.url,
                content=json.dumps(checkpoint, default=str),
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
            )

            if response.status_code < 300:
                return {"ok": True, "detail": f"{response.status_code} from {self.url}"}

            return {
                "ok": False,
                "detail": f"HTTP {response.status_code} from {self.url}",
            }
        except Exception as exc:  # сеть недоступна — анкор не должен ронять сервис
            logger.error("HTTP anchor failed: %s", exc)
            return {"ok": False, "detail": str(exc)}


class RekorAnchorTransport:
    """Публикует хеш коммитмента чекпоинта в Rekor (Sigstore), hashedrekord.

    СТАТУС (2026-08-24): транспорт реализован, покрыт юнит-тестами,
    включается только REKOR_ANCHOR=1 (по умолчанию ВЫКЛЮЧЕН). ЖИВОЙ ПРИЁМ
    ПОКА НЕ ДОСТИГНУТ — не включать для записи №1 до подтверждённого
    smoke-теста. Что уже выяснено живыми прогонами против
    rekor.sigstore.dev: apiVersion обязан быть '0.0.1' (не '0.1.0');
    publicKey.content = base64(PEM-ТЕКСТ), не base64(DER); ветка Эд25519
    принимает только algorithm='sha512' ('SHA-256 not in [SHA-512]');
    подпись верифицируется через x509-слой с опцией WithED25519ph — то
    есть Эд25519PH по RFC 8032 (прехеш), а пять наивных конструкций
    сообщения (raw value / sha512(value) / dom2-ph конкатенации / hexstr)
    инстанс отвергает как 'invalid signature'. Оставшийся шаг: точно
    воспроизвести ph-подпись (Go x/crypto SignWithOpts либо чистая
    реализация RFC 8032 §5.1) или перейти на RFC 3161 TSA, где CMS-токен
    проверяется офлайн без экзотических режимов.

    Замысел проверки у третьей стороны неизменен: файл чекпоинта ->
    пересчитать SHA-512 коммитмента -> сверить со значением в записи ->
    проверить подпись приложенным ключом -> inclusion-proof против
    публичного дерева Sigstore.

    КТО ПОДПИСЫВАЕТ. По умолчанию — ключ квитанций (RECEIPT_SIGNING_KEY):
    один и тот же ключ заверяет чекпоинт и его отпечаток в чужом логе.
    Без ключа в окружении — эфемерный режим, честно помеченный в
    результате (rekor_signed_by: ephemeral).

    409 Conflict трактуется как успех: запись уже в append-only логе.
    """

    name = "rekor"

    def __init__(
        self,
        url: Optional[str] = None,
        timeout: float = 15.0,
        signer: Optional[Any] = None,
    ):
        self.url = (
            url or os.getenv("REKOR_ANCHOR_URL") or "https://rekor.sigstore.dev"
        ).rstrip("/")
        self.timeout = timeout
        self._signer = signer

    # --- подписант -----------------------------------------------------

    @staticmethod
    def _default_signer() -> Any:
        """Ключ квитанций, если он есть в окружении/.env; иначе эфемерный."""
        from sia.config import resolve_env

        key = resolve_env("RECEIPT_SIGNING_KEY")

        if key:
            from .cryptographic_receipts import ReceiptGenerator

            return _ReceiptKeySigner(ReceiptGenerator(key))

        return _EphemeralSigner()

    def _signer_ready(self) -> Any:
        if self._signer is None:
            self._signer = self._default_signer()

        return self._signer

    # --- тело записи ---------------------------------------------------

    def _hashedrekord_body(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        from .receipt_registry import _checkpoint_commitment

        signer = self._signer_ready()
        # Rekor верифицирует подпись над sha512(декодированное значение
        # хеша) — двойной SHA-512 подтверждён живым прогоном (без него:
        # 'ed25519: invalid signature').
        value = hashlib.sha512(_checkpoint_commitment(checkpoint)).digest()
        message = hashlib.sha512(value).digest()

        return {
            # ВНИМАНИЕ: публичный инстанс регистрирует hashedrekord именно
            # под 0.0.1 — с '0.1.0' отвечает 'entry for version not found'.
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {
                    "hash": {
                        "algorithm": "sha512",
                        "value": value.hex(),
                    }
                },
                "signature": {
                    "content": base64.b64encode(signer.sign(message)).decode("ascii"),
                    "publicKey": {"content": signer.public_pem_b64},
                },
            },
        }

    def publish(self, checkpoint: dict[str, Any]) -> dict[str, Any]:
        try:
            signer = self._signer_ready()
            body = self._hashedrekord_body(checkpoint)
        except Exception as exc:
            logger.error("Rekor anchor: cannot build entry: %s", exc)
            return {"ok": False, "detail": f"cannot build entry: {exc}"}

        try:
            validate_webhook_url(self.url)
        except ValueError as exc:
            logger.error("Rekor anchor URL rejected (SSRF guard): %s", exc)
            return {"ok": False, "detail": f"rejected: {exc}"}

        try:
            import httpx

            response = httpx.post(
                f"{self.url}/api/v1/log/entries",
                json=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )

            if response.status_code in (200, 201):
                payload = response.json()
                entry_uuid = (
                    next(iter(payload), None) if isinstance(payload, dict) else None
                )
                entry = (
                    payload.get(entry_uuid, {}) if isinstance(payload, dict) else {}
                )
                return {
                    "ok": True,
                    "detail": f"anchored in Rekor: {entry_uuid}",
                    "rekor_uuid": entry_uuid,
                    "rekor_index": entry.get("logIndex"),
                    "rekor_signed_by": signer.signed_by,
                }

            if response.status_code == 409:
                return {
                    "ok": True,
                    "detail": "already anchored: Rekor returned 409 Conflict",
                    "rekor_signed_by": signer.signed_by,
                }

            return {
                "ok": False,
                "detail": (
                    f"HTTP {response.status_code} from {self.url}: "
                    f"{(response.text or '')[:200]}"
                ),
            }
        except Exception as exc:  # сеть недоступна — анкор не должен ронять сервис
            logger.error("Rekor anchor failed: %s", exc)
            return {"ok": False, "detail": str(exc)}


class _ReceiptKeySigner:
    """Подписывает дайджест тем же ключом, что и чекпоинт леджера."""

    signed_by = "receipt-key"

    def __init__(self, generator: Any):
        import base64 as _b64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        self._generator = generator
        raw = _b64.b64decode(generator.get_public_key())
        pem = Ed25519PublicKey.from_public_bytes(raw).public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        self.public_pem_b64 = _b64.b64encode(pem).decode("ascii")

    def sign(self, payload: bytes) -> bytes:
        import base64 as _b64

        return _b64.b64decode(self._generator.sign_bytes(payload))


class _EphemeralSigner:
    """Эфемерный ключ: существование дайджеста доказывает, подписанта
    чекпоинта связать нельзя — результат честно несёт signed_by=ephemeral."""

    signed_by = "ephemeral"

    def __init__(self):
        import base64 as _b64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        self._key = Ed25519PrivateKey.generate()
        pem = self._key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )
        self.public_pem_b64 = _b64.b64encode(pem).decode("ascii")

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)


def publish_checkpoint(
    checkpoint: dict[str, Any],
    transports: Optional[list[AnchorTransport]] = None,
) -> list[dict[str, Any]]:
    """Публикует чекпоинт через все транспорты.

    Транспорты по умолчанию собираются из окружения: файловый всегда
    (ANCHORS_DIR), HTTP — если задан ANCHOR_URL, Rekor — если включён
    REKOR_ANCHOR=1. Ошибка одного транспорта не влияет на остальные;
    результат возвращается по каждому.
    """
    if transports is None:
        transports = [FileAnchorTransport()]

        if os.getenv("ANCHOR_URL"):
            transports.append(HttpAnchorTransport())

        # Публичный свидетель: флаг ставится ДО первого аудита — якорь,
        # дописанный после записи №1, доказывает меньше (см. README).
        if os.getenv("REKOR_ANCHOR") == "1":
            transports.append(RekorAnchorTransport())

    return [
        {"transport": t.name, **t.publish(checkpoint)} for t in transports
    ]
