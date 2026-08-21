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
  сторонний timestamping-сервис).

Сравнивая внешний анкор с текущей головой цепочки, любой аудитор
доказуемо фиксирует, что история не переписывалась с момента анкора.
"""
from __future__ import annotations

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


def publish_checkpoint(
    checkpoint: dict[str, Any],
    transports: Optional[list[AnchorTransport]] = None,
) -> list[dict[str, Any]]:
    """Публикует чекпоинт через все транспорты.

    Транспорты по умолчанию собираются из окружения: файловый всегда
    (ANCHORS_DIR), HTTP — если задан ANCHOR_URL. Ошибка одного транспорта
    не влияет на остальные; результат возвращается по каждому.
    """
    if transports is None:
        transports = [FileAnchorTransport()]

        if os.getenv("ANCHOR_URL"):
            transports.append(HttpAnchorTransport())

    return [
        {"transport": t.name, **t.publish(checkpoint)} for t in transports
    ]
