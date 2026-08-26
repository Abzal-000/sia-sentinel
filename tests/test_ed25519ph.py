"""Ed25519ph (sentinel/ed25519ph) — эталон, на котором стоит Rekor-якорь.

Самотест модуля (вектор RFC 8032 §7.3 побайтово + перекрёстные проверки
с pyca + ловушка «лишнего хеша», в которую уже падали живые прогоны)
закреплён в общем suite: регрессия арифметики не может пройти незаметно.
"""
from __future__ import annotations

import hashlib
import unittest


class Ed25519PhSelfTestCase(unittest.TestCase):
    def test_reference_module_selftest_passes(self) -> None:
        from sentinel import ed25519ph

        self.assertEqual(ed25519ph.selftest(), 0)

    def test_receipt_generator_signs_ph_as_receipt_key(self) -> None:
        """sign_ph_digest использует тот же детерминированный seed, что и
        обычные квитанции: подпись верифицируется публичным ключом
        генератора — подписант остаётся receipt-key, а не ephemeral."""
        from sentinel.cryptographic_receipts import ReceiptGenerator
        from sentinel.ed25519ph import verify_digest

        generator = ReceiptGenerator("unit-test-seed-material")
        message = b'{"protocol":"sia-preregistration/4"}'
        digest = hashlib.sha512(message).digest()

        signature = generator.sign_ph_digest(digest)

        pub = base64_public_key(generator)
        self.assertTrue(verify_digest(pub, digest, signature))
        # И ровно один хеш: ph над самим дайджестом НЕ проверяется
        self.assertFalse(verify_digest(pub, hashlib.sha512(digest).digest(),
                                       signature))


def base64_public_key(generator) -> bytes:
    import base64

    return base64.b64decode(generator.get_public_key())


if __name__ == "__main__":
    unittest.main()
