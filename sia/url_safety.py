"""SSRF-защита для пользовательских URL во флоу-конфигурациях.

ДЫРА, которую закрывает этот модуль
-----------------------------------
`base_url` LLM-эндпоинта приходил из пользовательского флоу (sentinel API ->
flow_runner._endpoint_from_block) и уходил в OpenAI-совместимый клиент БЕЗ
проверки назначения. В сочетании с `api_key_env` (тоже из флоу) это давало
полную цепочку эксфильтрации: пользователь указывал чужой/внутренний
`base_url` и имя env-переменной с секретом — сервис отправлял секрет на
указанный хост. Плюс сам `base_url` — классический SSRF во внутреннюю сеть
(metadata 169.254.169.254, localhost, приватные диапазоны).

Модуль повторяет проверенный подход из sentinel/outbound_webhooks.py
(SSRF-защита D11), но живёт в sia, потому что sia не должен импортировать
sentinel (sentinel зависит от sia, не наоборот).

Защита:
- Хост-IP-литерал проверяется напрямую (включая IPv4-mapped IPv6).
- Имя резолвится, и проверяются ВСЕ полученные адреса.
- Отклоняются: private, loopback, link-local (в т.ч. облачный metadata
  169.254.169.254), reserved, multicast, unspecified.
- Если имя не резолвится — URL отклоняется для исходящих ЗАПРОСОВ с секретом:
  подключаться не к чему, но и доверять нельзя; безопаснее отказать. (В отличие
  от вебхуков, где отказ ломает доставку, здесь мы лучше не отправим секрет.)
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Разрешённые env-переменные для api_key_env (белый список провайдеров).
#
# Без белого списка пользовательский флоу мог указать ЛЮБОЕ имя переменной
# (например RECEIPT_SIGNING_KEY или PLATFORM_ADMIN_API_KEY) и заставить сервис
# подставить её значение в Authorization-заголовок к атакуемому base_url —
# полная эксфильтрация секретов процесса. Теперь разрешены только ключи
# известных провайдеров, чей base_url одновременно проходит SSRF-проверку.
ALLOWED_API_KEY_ENVS = frozenset(
    {
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GROQ_API_KEY",
        "NVIDIA_API_KEY",
        "OPENROUTER_API_KEY",
        "TOGETHER_API_KEY",
        "DEEPSEEK_API_KEY",
        "MISTRAL_API_KEY",
        "GEMINI_API_KEY",
        "XAI_API_KEY",
    }
)


def is_forbidden_ip(
    ip: "ipaddress.IPv4Address | ipaddress.IPv6Address",
) -> bool:
    """Внутренний/служебный адрес, недостижимый для внешних исходящих вызовов."""
    # IPv4-mapped IPv6 (::ffff:10.0.0.1) проверяем как IPv4
    mapped = getattr(ip, "ipv4_mapped", None)

    if mapped is not None:
        ip = mapped

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def assert_safe_outbound_url(url: str) -> str:
    """Проверяет, что URL ведёт на внешний (не внутренний) адрес.

    Args:
        url: пользовательский URL (например base_url LLM-эндпоинта).

    Returns:
        Нормализованный (исходный) URL, если он безопасен.

    Raises:
        ValueError: URL пуст, не имеет хоста, использует не http(s), ведёт на
            внутренний адрес или его хост не резолвится.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")

    parsed = urlparse(url.strip())

    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL must be http(s): {url}")

    hostname = parsed.hostname

    if not hostname:
        raise ValueError(f"URL has no host: {url}")

    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if is_forbidden_ip(literal):
            raise ValueError(
                f"URL points to a forbidden internal address: {hostname}"
            )
        return url

    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        # Для исходящего вызова с секретом неразрешимое имя — повод отказать,
        # а не рискнуть отправкой ключа неизвестному хосту.
        raise ValueError(f"URL host does not resolve: {hostname}") from exc

    for info in infos:
        resolved = ipaddress.ip_address(info[4][0])

        if is_forbidden_ip(resolved):
            raise ValueError(
                f"URL host {hostname} resolves to a forbidden internal "
                f"address: {resolved}"
            )

    return url
