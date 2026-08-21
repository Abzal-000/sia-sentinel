"""Исходящие webhooks: уведомления подписчиков о событиях аудита.

Тенант подписывает URL на события (audit.completed / audit.failed); при
наступлении события диспетчер доставляет POST с JSON-payload, подписанный
HMAC-SHA256 секретом подписки (заголовок X-SIA-Signature). Подписчик
проверяет подпись, чтобы убедиться, что уведомление пришло от Sentinel.

Доставка fire-and-forget в daemon-потоке: недоступный URL подписчика не
должен влиять на аудит. Ретраев нет (прототип); ошибки только логируются.

Секрет подписки возвращается один раз при создании подписки и больше не
показывается (паттерн API-ключей).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

EVENT_AUDIT_COMPLETED = "audit.completed"
EVENT_AUDIT_FAILED = "audit.failed"
KNOWN_EVENTS = (EVENT_AUDIT_COMPLETED, EVENT_AUDIT_FAILED)

SIGNATURE_HEADER = "X-SIA-Signature"
DELIVERY_TIMEOUT = 10.0


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def compute_signature(secret: str, body: bytes) -> str:
    """HMAC-SHA256 подпись тела уведомления: 'sha256=<hex>'."""
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    """Проверка подписи на стороне подписчика (constant-time)."""
    expected = compute_signature(secret, body)
    return hmac.compare_digest(expected, signature)


def _default_transport(url: str, headers: dict[str, str], body: bytes) -> None:
    import httpx

    httpx.post(url, content=body, headers=headers, timeout=DELIVERY_TIMEOUT)


@dataclass
class WebhookSubscription:
    subscription_id: str
    tenant_id: str
    url: str
    events: list[str]
    secret: str
    active: bool = True
    created_at: str = field(default_factory=_utcnow)

    def to_dict(self, include_secret: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "subscription_id": self.subscription_id,
            "tenant_id": self.tenant_id,
            "url": self.url,
            "events": list(self.events),
            "active": self.active,
            "created_at": self.created_at,
        }

        if include_secret:
            data["secret"] = self.secret

        return data


class OutboundWebhookDispatcher:
    """Подписки + доставка событий.

    transport(url, headers, body) — вызов доставки; по умолчанию httpx POST.
    В тестах передаётся мок-транспорт, чтобы не ходить в сеть.
    """

    def __init__(
        self,
        subscriptions_file: Optional[str] = None,
        transport: Optional[Callable[[str, dict[str, str], bytes], None]] = None,
    ):
        self.subscriptions_file = Path(
            subscriptions_file or os.getenv("WEBHOOKS_FILE", "webhooks.json")
        )
        self._transport = transport or _default_transport
        self._subscriptions: dict[str, WebhookSubscription] = {}
        self._lock = threading.Lock()
        self._load()

    # === Управление подписками ===

    def subscribe(
        self,
        tenant_id: str,
        url: str,
        events: list[str],
        secret: Optional[str] = None,
    ) -> WebhookSubscription:
        """Создаёт подписку; секрет генерируется, если не задан."""
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"Webhook URL must be http(s): {url}")

        unknown = [e for e in events if e not in KNOWN_EVENTS]

        if unknown:
            raise ValueError(
                f"Unknown events: {unknown}. Known: {list(KNOWN_EVENTS)}"
            )

        if not events:
            raise ValueError("At least one event is required")

        subscription = WebhookSubscription(
            subscription_id=f"wh-{uuid.uuid4().hex[:12]}",
            tenant_id=tenant_id,
            url=url,
            events=list(events),
            secret=secret or secrets.token_hex(32),
        )

        with self._lock:
            self._subscriptions[subscription.subscription_id] = subscription
            self._save()

        return subscription

    def unsubscribe(self, subscription_id: str, tenant_id: str) -> bool:
        """Удаляет подписку; чужая подписка -> False (изоляция)."""
        with self._lock:
            subscription = self._subscriptions.get(subscription_id)

            if subscription is None or subscription.tenant_id != tenant_id:
                return False

            del self._subscriptions[subscription_id]
            self._save()

        return True

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        """Подписки тенанта (без секретов)."""
        with self._lock:
            return [
                s.to_dict()
                for s in self._subscriptions.values()
                if s.tenant_id == tenant_id
            ]

    def get(self, subscription_id: str, tenant_id: str) -> Optional[WebhookSubscription]:
        with self._lock:
            subscription = self._subscriptions.get(subscription_id)

            if subscription is None or subscription.tenant_id != tenant_id:
                return None

            return subscription

    # === Доставка ===

    def dispatch(self, event: str, payload: dict[str, Any]) -> int:
        """Доставляет событие активным подписчикам тенанта; возвращает их число.

        Тенант берётся из payload["tenant_id"] — подписчики других тенантов
        событие не получают. Доставка асинхронная (daemon-поток на
        подписчика); ошибки доставки логируются и не пробрасываются.
        """
        tenant_id = payload.get("tenant_id")
        body = json.dumps(payload, default=str).encode("utf-8")
        targets: list[WebhookSubscription] = []

        with self._lock:
            for subscription in self._subscriptions.values():
                if (
                    subscription.active
                    and event in subscription.events
                    and subscription.tenant_id == tenant_id
                ):
                    targets.append(subscription)

        for subscription in targets:
            headers = {
                "Content-Type": "application/json",
                "X-SIA-Event": event,
                SIGNATURE_HEADER: compute_signature(subscription.secret, body),
            }

            worker = threading.Thread(
                target=self._deliver,
                args=(subscription.url, headers, body),
                name=f"webhook-{subscription.subscription_id[:8]}",
                daemon=True,
            )
            worker.start()

        return len(targets)

    def _deliver(self, url: str, headers: dict[str, str], body: bytes) -> None:
        try:
            self._transport(url, headers, body)
        except Exception as exc:  # подписчик недоступен — аудит не должен страдать
            logger.warning("Webhook delivery to %s failed: %s", url, exc)

    # === Персистентность ===

    def _load(self) -> None:
        if not self.subscriptions_file.exists():
            return

        try:
            with open(self.subscriptions_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return

        for item in data.get("subscriptions", []):
            subscription = WebhookSubscription(
                subscription_id=item["subscription_id"],
                tenant_id=item["tenant_id"],
                url=item["url"],
                events=item.get("events", []),
                secret=item.get("secret", ""),
                active=item.get("active", True),
                created_at=item.get("created_at", _utcnow()),
            )
            self._subscriptions[subscription.subscription_id] = subscription

    def _save(self) -> None:
        data = {
            "subscriptions": [
                s.to_dict(include_secret=True) for s in self._subscriptions.values()
            ]
        }

        with open(self.subscriptions_file, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
