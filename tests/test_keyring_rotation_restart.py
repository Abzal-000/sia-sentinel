"""Регрессионный тест: keyring переживает ротацию ключа и рестарт процесса.

ДЫРА, которую закрывает этот файл
--------------------------------
При ротации ключа активный генератор переключается, а объявления СТАРЫХ ключей
остаются в подписанном леджере навсегда. Но in-memory keyring при старте
процесса наполнялся ТОЛЬКО текущим активным ключом. Сценарий:

  1) подпись квитанции ключом K1;
  2) ротация на K2 (K1 остаётся в цепочке как объявленный ключ);
  3) рестарт процесса → keyring = {K2} (+fallback K2).

После рестарта квитанция, подписанная K1, НЕ проходит verify (по kid K1 ключа
в keyring нет). То есть система не может проверить собственную историю после
рестарта — прямое противоречие гарантии «квитанции остаются проверяемыми после
ротации» (C3) и доверительной модели продукта.

Тест ниже моделирует рестарт (новый KeyringVerifier, гидратация деклараций из
леджера) и требует, чтобы старая квитанция снова проверялась.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.cryptographic_receipts import (
    KeyringVerifier,
    ReceiptGenerator,
)
from sentinel.receipt_registry import ReceiptRegistry


def _hydrate(keyring: KeyringVerifier, registry: ReceiptRegistry) -> None:
    """Гидратация keyring декларациями из леджера (как в api.py)."""
    for declaration in registry.key_declarations():
        decl = declaration.get("declaration") or {}
        kid = decl.get("kid")
        public_key = decl.get("public_key")
        if kid and public_key:
            keyring.add_key(kid, public_key)


class KeyringSurvivesRotationRestartTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.registry = ReceiptRegistry(str(Path(self._tmp.name) / "receipts"))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_old_receipt_verifiable_after_rotation_and_restart(self) -> None:
        gen1 = ReceiptGenerator("seed-one-deterministic")

        # 1) Квитанция, подписанная первым ключом.
        signed1 = gen1.generate_receipt("e1", "code-one", True, "high")
        self.assertTrue(gen1.verify_receipt(signed1))
        self.assertEqual(signed1.kid, gen1.kid)

        # 2) Ротация: объявляем K2, подписанный K1 (как в проде).
        gen2 = ReceiptGenerator("seed-two-deterministic")
        self.assertNotEqual(gen1.kid, gen2.kid)
        self.registry.register_key_declaration(
            kid=gen1.kid, public_key=gen1.get_public_key(), generator=gen1
        )
        self.registry.register_key_declaration(
            kid=gen2.kid, public_key=gen2.get_public_key(), generator=gen1
        )

        # 3) Рестарт: keyring наполняется ТОЛЬКО текущим активным ключом.
        #    Это было поведение ДО фикса.
        keyring = KeyringVerifier(gen2.get_public_key())
        keyring.add_key(gen2.kid, gen2.get_public_key())

        self.assertFalse(
            keyring.verify(signed1),
            "pre-fix behaviour: old receipt unverified after restart",
        )

        # 4) Фикс: гидратируем keyring ВСЕМИ объявлениями из леджера.
        _hydrate(keyring, self.registry)

        self.assertTrue(
            keyring.verify(signed1),
            "after hydration, old receipt must verify via its declared kid",
        )

    def test_hydration_loads_every_declared_key_idempotently(self) -> None:
        gens = [ReceiptGenerator(f"seed-{i}-det") for i in range(3)]
        for gen in gens:
            self.registry.register_key_declaration(
                kid=gen.kid, public_key=gen.get_public_key(), generator=gens[0]
            )

        self.assertEqual(len(self.registry.key_declarations()), 3)

        keyring = KeyringVerifier(gens[-1].get_public_key())
        _hydrate(keyring, self.registry)
        _hydrate(keyring, self.registry)  # идемпотентно

        for gen in gens:
            self.assertIn(gen.kid, keyring._keys)

    def test_forged_receipt_still_rejected_after_hydration(self) -> None:
        """Гидратация не ослабляет проверку: подделка не проходит."""
        gen1 = ReceiptGenerator("seed-one-deterministic")
        self.registry.register_key_declaration(
            kid=gen1.kid, public_key=gen1.get_public_key(), generator=gen1
        )

        keyring = KeyringVerifier(gen1.get_public_key())
        _hydrate(keyring, self.registry)

        # Квитанция, подписанная ключом, НЕ объявленным в цепочке.
        rogue = ReceiptGenerator("rogue-key-not-declared")
        forged = rogue.generate_receipt("e-forged", "code-forged", True, "high")
        self.assertNotIn(forged.kid, keyring._keys)
        self.assertFalse(keyring.verify(forged))

    def test_tampered_receipt_rejected(self) -> None:
        """Подмена подписанного содержимого ломает проверку."""
        gen = ReceiptGenerator("seed-one-deterministic")
        self.registry.register_key_declaration(
            kid=gen.kid, public_key=gen.get_public_key(), generator=gen
        )
        keyring = KeyringVerifier(gen.get_public_key())
        _hydrate(keyring, self.registry)

        receipt = gen.generate_receipt("e1", "code-one", True, "high")
        receipt.safety_approved = False  # подмена после подписи
        self.assertFalse(keyring.verify(receipt))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
