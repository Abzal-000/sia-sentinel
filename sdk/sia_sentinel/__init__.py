"""SIA Sentinel Python SDK.

Тонкий клиент поверх HTTP API Sentinel: аудиты Proof-of-Savings,
Savings Autopilot, квитанции, леджер TrustChain, тенанты и биллинг.

Быстрый старт:

    from sia_sentinel import SentinelClient

    client = SentinelClient("https://sentinel.example.com", api_key="sk-...")
    result = client.run_audit(flow)
    print(result["registry_id"])
"""
from .client import SentinelAPIError, SentinelClient

__all__ = ["SentinelClient", "SentinelAPIError"]
__version__ = "0.1.0"
