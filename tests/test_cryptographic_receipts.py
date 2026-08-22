import unittest
from sentinel.cryptographic_receipts import ReceiptGenerator, ReceiptVerifier, CryptographicReceipt


class CryptographicReceiptsTestCase(unittest.TestCase):
    """Test cryptographic receipt generation and verification."""

    def setUp(self) -> None:
        """Set up test fixtures."""
        self.signing_key = "test-secret-key-12345"
        self.generator = ReceiptGenerator(self.signing_key)
        # Верификатор строится только из публичного ключа (H2)
        self.verifier = ReceiptVerifier(self.generator.get_public_key())

    def test_generate_receipt(self) -> None:
        """Test receipt generation."""
        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        self.assertIsNotNone(receipt.receipt_id)
        self.assertEqual(receipt.evidence_id, "evidence-123")
        self.assertTrue(receipt.safety_approved)
        self.assertEqual(receipt.trust_level, "JUNIOR")
        self.assertIsNotNone(receipt.signature)

    def test_verify_valid_receipt(self) -> None:
        """Test verification of valid receipt."""
        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        is_valid = self.verifier.verify(receipt)
        self.assertTrue(is_valid)

    def test_verify_tampered_receipt(self) -> None:
        """Test verification fails for tampered receipt."""
        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        # Tamper with receipt
        receipt.safety_approved = False

        is_valid = self.verifier.verify(receipt)
        self.assertFalse(is_valid)

    def test_verify_wrong_key(self) -> None:
        """Test verification fails with wrong key."""
        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        other_generator = ReceiptGenerator("another-secret")
        wrong_verifier = ReceiptVerifier(other_generator.get_public_key())
        is_valid = wrong_verifier.verify(receipt)
        self.assertFalse(is_valid)

    def test_receipt_json_serialization(self) -> None:
        """Test JSON serialization and deserialization."""
        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        receipt_json = receipt.to_json()

        is_valid = self.verifier.verify_json(receipt_json)
        self.assertTrue(is_valid)

    def test_different_code_different_hash(self) -> None:
        """Test different code produces different hash."""
        receipt1 = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        receipt2 = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return b + a",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        self.assertNotEqual(receipt1.code_hash, receipt2.code_hash)

    def test_same_code_same_hash(self) -> None:
        """Test same code produces same hash."""
        code = "def add(a, b): return a + b"

        receipt1 = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code=code,
            safety_approved=True,
            trust_level="JUNIOR",
        )

        receipt2 = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code=code,
            safety_approved=True,
            trust_level="JUNIOR",
        )

        self.assertEqual(receipt1.code_hash, receipt2.code_hash)

    def test_verify_with_public_key_only(self) -> None:
        """Third party verifies with the published public key, no secret."""
        public_key = self.generator.get_public_key()

        verifier = ReceiptVerifier(public_key)

        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        self.assertTrue(verifier.verify(receipt))

        receipt.trust_level = "SENIOR"
        self.assertFalse(verifier.verify(receipt))

    def test_public_key_cannot_sign(self) -> None:
        """A verifier built from the public key cannot forge receipts."""
        public_key = self.generator.get_public_key()
        verifier = ReceiptVerifier(public_key)

        forged = CryptographicReceipt(
            receipt_id="fake",
            evidence_id="evidence-123",
            code_hash="abc",
            safety_approved=True,
            trust_level="SENIOR",
            timestamp=1.0,
            nonce="nonce",
            signature="AA",
        )

        self.assertFalse(verifier.verify(forged))

    def test_default_key_from_env(self) -> None:
        """Generator falls back to RECEIPT_SIGNING_KEY env var."""
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"RECEIPT_SIGNING_KEY": "env-secret"}):
            from sentinel.cryptographic_receipts import ReceiptGenerator as RG
            gen = RG()
            verifier = ReceiptVerifier(gen.get_public_key())
            receipt = gen.generate_receipt(
                evidence_id="e1",
                code="x = 1",
                safety_approved=True,
                trust_level="NOVICE",
            )
            self.assertTrue(verifier.verify(receipt))


    def test_receipt_with_manifest(self) -> None:
        """Receipt carries a reproducibility manifest covered by the signature."""
        manifest = {
            "environment": {"python": "3.11.15"},
            "old_code_sha256": "a" * 64,
            "seeds": [42],
        }

        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
            manifest=manifest,
        )

        self.assertEqual(receipt.manifest, manifest)
        self.assertTrue(self.verifier.verify(receipt))

    def test_manifest_tamper_detected(self) -> None:
        """Tampering with the manifest breaks the signature."""
        manifest = {"environment": {"python": "3.11.15"}, "seeds": [42]}

        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
            manifest=manifest,
        )

        receipt.manifest["seeds"] = [1, 2, 3]

        self.assertFalse(self.verifier.verify(receipt))

    def test_manifest_verified_with_public_key_only(self) -> None:
        """Third party verifies a manifest-bearing receipt with the public key."""
        verifier = ReceiptVerifier(self.generator.get_public_key())

        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
            manifest={"pricing": {"compute_usd_per_hour": 2.0}},
        )

        self.assertTrue(verifier.verify(receipt))
        self.assertTrue(verifier.verify_json(receipt.to_json()))

    def test_receipt_without_manifest_still_valid(self) -> None:
        """Backward compatibility: receipts without a manifest verify as before."""
        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        self.assertIsNone(receipt.manifest)
        self.assertTrue(self.verifier.verify(receipt))

    def test_receipt_id_covered_by_signature(self) -> None:
        """H1: подмена receipt_id ломает подпись (replay на другой id)."""
        receipt = self.generator.generate_receipt(
            evidence_id="evidence-123",
            code="def add(a, b): return a + b",
            safety_approved=True,
            trust_level="JUNIOR",
        )

        self.assertTrue(self.verifier.verify(receipt))

        receipt.receipt_id = "forged-receipt-id"
        self.assertFalse(self.verifier.verify(receipt))

    def test_verifier_rejects_seed_material(self) -> None:
        """H2: верификатор принимает только публичный ключ, не сид."""
        with self.assertRaises(ValueError):
            ReceiptVerifier(self.signing_key)

        with self.assertRaises(ValueError):
            ReceiptVerifier("not-base64-!!!")

        # 16 байт base64 — валидный base64, но не 32-байтный ключ
        import base64
        with self.assertRaises(ValueError):
            ReceiptVerifier(base64.b64encode(b"0123456789abcdef").decode())


class GeneratorKeyResolutionTestCase(unittest.TestCase):
    """Блокер маяка: секрет читается через resolve_env, эфемерный — только явно."""

    def test_bare_generator_without_secret_raises(self) -> None:
        # Раньше молча генерировался эфемерный ключ: чек подписывался
        # личностью, исчезающей с рестартом, без единого сообщения
        from unittest.mock import patch

        with patch("sentinel.cryptographic_receipts.resolve_env", return_value=None):
            with self.assertRaises(ValueError) as ctx:
                ReceiptGenerator()

        self.assertIn("RECEIPT_SIGNING_KEY", str(ctx.exception))
        self.assertIn("ephemeral", str(ctx.exception))

    def test_explicit_allow_ephemeral_works(self) -> None:
        from unittest.mock import patch

        with patch("sentinel.cryptographic_receipts.resolve_env", return_value=None):
            generator = ReceiptGenerator(allow_ephemeral=True)

        self.assertTrue(generator.kid)  # ключ создан

    def test_resolves_secret_via_resolve_env(self) -> None:
        # .env-резолв: секрет, заданный только в .env (не в окружении),
        # раньше молча игнорировался сырым os.getenv
        from unittest.mock import patch

        with patch(
            "sentinel.cryptographic_receipts.resolve_env",
            return_value="env-or-dotenv-material",
        ) as mocked:
            resolved = ReceiptGenerator()

        mocked.assert_called_once_with("RECEIPT_SIGNING_KEY")
        self.assertEqual(
            resolved.kid,
            ReceiptGenerator("env-or-dotenv-material").kid,
        )


if __name__ == "__main__":
    unittest.main()
