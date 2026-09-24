"""Регрессионные тесты SSRF + эксфильтрации секретов через flow-конфиг.

ДЫРА, которую закрывает этот файл
--------------------------------
`base_url` и `api_key_env` LLM-эндпоинта приходили из пользовательского флоу и
уходили в OpenAI-совместимый клиент без проверки. Атакующий мог:
  1) указать внутренний `base_url` (localhost / 127.0.0.1 / облачный metadata
     169.254.169.254) -> классический SSRF во внутреннюю сеть;
  2) указать `api_key_env` = произвольное имя переменной процесса
     (RECEIPT_SIGNING_KEY, PLATFORM_ADMIN_API_KEY, ...) + свой `base_url` ->
     сервис подставлял секрет в Authorization-заголовок и отправлял его атакующему.

Теперь: base_url проверяется (SSRF), api_key_env ограничен белым списком
провайдеров (эксфильтрация закрыта).
"""
from __future__ import annotations

import unittest

from sia.flow_runner import _endpoint_from_block
from sia.url_safety import ALLOWED_API_KEY_ENVS, assert_safe_outbound_url


class UrlSafetyTestCase(unittest.TestCase):
    """SSRF-защита: внутренние адреса отвергаются."""

    def test_loopback_literal_rejected(self) -> None:
        for url in (
            "http://127.0.0.1/v1",
            "http://127.0.0.1:8080/v1",
            "https://localhost/v1",
            "http://[::1]/v1",
        ):
            with self.assertRaises(ValueError, msg=url):
                assert_safe_outbound_url(url)

    def test_cloud_metadata_rejected(self) -> None:
        # AWS/GCP metadata — классическая цель SSRF.
        with self.assertRaises(ValueError):
            assert_safe_outbound_url("http://169.254.169.254/latest/meta-data/")

    def test_private_ranges_rejected(self) -> None:
        for url in (
            "http://10.0.0.1/v1",
            "http://192.168.1.1/v1",
            "http://172.16.0.1/v1",
        ):
            with self.assertRaises(ValueError, msg=url):
                assert_safe_outbound_url(url)

    def test_non_http_scheme_rejected(self) -> None:
        for url in ("file:///etc/passwd", "ftp://example.com", "gopher://x"):
            with self.assertRaises(ValueError, msg=url):
                assert_safe_outbound_url(url)

    def test_empty_or_hostless_rejected(self) -> None:
        for url in ("", "   ", "http://"):
            with self.assertRaises(ValueError, msg=url):
                assert_safe_outbound_url(url)

    def test_public_host_allowed(self) -> None:
        # Публичный IP-литерал — разрешён.
        self.assertEqual(
            assert_safe_outbound_url("https://8.8.8.8/v1"), "https://8.8.8.8/v1"
        )


class EndpointBlockSecurityTestCase(unittest.TestCase):
    """Защита на уровне сборки эндпоинта из пользовательского блока."""

    def test_internal_base_url_rejected_before_key_resolution(self) -> None:
        """base_url во внутреннюю сеть отвергается ДО подстановки ключа.

        Даже если api_key_env указывает на разрешённую переменную, отправлять
        ключ на внутренний хост нельзя — валидация идёт первой.
        """
        with self.assertRaises(ValueError):
            _endpoint_from_block(
                {
                    "model_name": "evil",
                    "base_url": "http://169.254.169.254/",
                    "api_key_env": "GROQ_API_KEY",
                }
            )

    def test_non_allowlisted_api_key_env_rejected(self) -> None:
        """Произвольная env-переменная процесса не подставляется в заголовок."""
        # Публичный IP, чтобы дойти до проверки allowlist (SSRF-фильтр проходит).
        with self.assertRaises(ValueError) as ctx:
            _endpoint_from_block(
                {
                    "model_name": "evil",
                    "base_url": "https://8.8.8.8/v1",
                    "api_key_env": "RECEIPT_SIGNING_KEY",
                }
            )
        self.assertIn("not an allowed provider key", str(ctx.exception))

    def test_platform_admin_key_env_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _endpoint_from_block(
                {
                    "model_name": "evil",
                    "base_url": "https://8.8.8.8/v1",
                    "api_key_env": "PLATFORM_ADMIN_API_KEY",
                }
            )

    def test_allowlisted_env_accepted(self) -> None:
        """Разрешённая провайдерская переменная проходит (если хост безопасен)."""
        # Хост не резолвится в тестовой среде -> ValueError от SSRF-проверки,
        # НО не от allowlist. Проверяем именно allowlist, подменяя безопасный
        # публичный IP, чтобы дойти до резолва ключа.
        import os

        os.environ["GROQ_API_KEY"] = "test-key-not-real"
        try:
            endpoint = _endpoint_from_block(
                {
                    "model_name": "llama",
                    "base_url": "https://8.8.8.8/v1",  # публичный IP
                    "api_key_env": "GROQ_API_KEY",
                }
            )
            self.assertEqual(endpoint.api_key, "test-key-not-real")
        finally:
            del os.environ["GROQ_API_KEY"]

    def test_no_base_url_no_key_still_builds(self) -> None:
        """simulated-конфигурация без base_url/ключа собирается как раньше."""
        endpoint = _endpoint_from_block({"model_name": "sim-model"})
        self.assertIsNone(endpoint.base_url)
        self.assertIsNone(endpoint.api_key)

    def test_allowlist_contains_real_providers(self) -> None:
        # Белый список покрывает провайдеров, реально используемых в каталогах.
        for name in ("GROQ_API_KEY", "NVIDIA_API_KEY", "OPENROUTER_API_KEY"):
            self.assertIn(name, ALLOWED_API_KEY_ENVS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
