from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from audit_cli import main, to_markdown


CODE_FLOW = {
    "kind": "code",
    "name": "fib-test-flow",
    "function_name": "fib",
    "old_code": "def fib(n):\n    if n <= 1:\n        return n\n    return fib(n - 1) + fib(n - 2)\n",
    "new_code": "def fib(n):\n    a, b = 0, 1\n    for _ in range(n):\n        a, b = b, a + b\n    return a\n",
    "test_suite": ["assert fib(10) == 55"],
    "args_template": [15],
    "performance_iterations": 50,
    "performance_repeat": 2,
    "pricing": {"compute_usd_per_hour": 3.6},
}

LLM_FLOW = {
    "kind": "llm_flow",
    "name": "router-test-flow",
    "dataset": [
        {"prompt": "What is 2+2?", "expect_contains": "4"},
        {"prompt": "Capital of France?", "expect_contains": "Paris"},
    ],
    "old": {"model_name": "premium", "profile": "verbose",
            "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
    "new": {"model_name": "small", "profile": "concise",
            "input_token_usd_per_m": 0.1, "output_token_usd_per_m": 0.4},
    "repetitions": 2,
}


class AuditCLITestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_flow(self, flow: dict) -> str:
        flow_path = self.tmp / "flow.json"
        flow_path.write_text(json.dumps(flow), encoding="utf-8")
        return str(flow_path)

    def test_code_flow_end_to_end(self) -> None:
        flow_path = self._write_flow(CODE_FLOW)
        out_path = self.tmp / "report.json"
        md_path = self.tmp / "report.md"

        exit_code = main([
            "--flow", flow_path,
            "--out", str(out_path),
            "--markdown", str(md_path),
        ])

        self.assertEqual(exit_code, 0)

        report = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(report["kind"], "code")
        self.assertTrue(report["claim"]["savings_verified"])
        self.assertGreater(report["claim"]["savings_ratio"], 0.5)
        self.assertIn("manifest", report)

        markdown = md_path.read_text(encoding="utf-8")
        self.assertIn("Proof-of-Savings Report", markdown)
        self.assertIn("fib-test-flow", markdown)

    def test_llm_flow_end_to_end(self) -> None:
        flow_path = self._write_flow(LLM_FLOW)
        out_path = self.tmp / "llm_report.json"

        exit_code = main(["--flow", flow_path, "--out", str(out_path)])

        self.assertEqual(exit_code, 0)

        report = json.loads(out_path.read_text(encoding="utf-8"))
        self.assertEqual(report["kind"], "llm_flow")
        self.assertEqual(report["mode"], "simulated")
        self.assertTrue(report["claim"]["savings_verified"])
        self.assertEqual(report["usage_old"]["calls"], 4)
        self.assertEqual(report["usage_new"]["calls"], 4)

    def test_missing_flow_file_exits(self) -> None:
        with self.assertRaises(SystemExit):
            main(["--flow", str(self.tmp / "missing.json")])

    def test_signed_receipt_verifies(self) -> None:
        import os
        from unittest.mock import patch

        from sentinel.cryptographic_receipts import CryptographicReceipt, ReceiptVerifier

        flow_path = self._write_flow(LLM_FLOW)
        out_path = self.tmp / "report.json"
        receipt_path = self.tmp / "receipt.json"

        # Подпись требует стабильный ключ (эфемерный запрещён) — задаём
        # через окружение, как это делал бы оператор
        with patch.dict(os.environ, {"RECEIPT_SIGNING_KEY": "cli-test-signing-key"}):
            exit_code = main([
                "--flow", flow_path,
                "--out", str(out_path),
                "--sign", str(receipt_path),
            ])

        self.assertEqual(exit_code, 0)

        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        verification = receipt.pop("verification")

        self.assertIn("manifest", receipt)
        verifier = ReceiptVerifier(verification["public_key"])
        self.assertTrue(verifier.verify(CryptographicReceipt(**receipt)))

        receipt["manifest"]["dataset_sha256"] = "tampered"
        self.assertFalse(verifier.verify(CryptographicReceipt(**receipt)))

    def test_sign_without_key_refuses_loudly(self) -> None:
        """Без RECEIPT_SIGNING_KEY подпись запрещена — с чистой ошибкой, не эфемерным ключом."""
        import os
        from unittest.mock import patch

        # Детерминированно: ни окружение, ни .env не содержат секрета
        env = {k: v for k, v in os.environ.items() if k != "RECEIPT_SIGNING_KEY"}

        with patch.dict(os.environ, env, clear=True), patch(
            "sentinel.cryptographic_receipts.resolve_env", return_value=None
        ):
            flow_path = self._write_flow(LLM_FLOW)
            out_path = self.tmp / "report.json"
            receipt_path = self.tmp / "receipt.json"

            with self.assertRaises(SystemExit) as ctx:
                main([
                    "--flow", flow_path,
                    "--out", str(out_path),
                    "--sign", str(receipt_path),
                ])

        message = str(ctx.exception)
        self.assertIn("Cannot sign", message)
        self.assertIn("RECEIPT_SIGNING_KEY", message)
        self.assertFalse(receipt_path.exists())  # чек не создан

    def test_markdown_generator_standalone(self) -> None:
        report = json.loads(json.dumps({
            "protocol": "proof-of-savings-llm/1",
            "name": "demo",
            "kind": "llm_flow",
            "mode": "simulated",
            "claim": {
                "savings_verified": True,
                "savings_ratio": 0.5,
                "old_unit_cost_usd": 0.002,
                "new_unit_cost_usd": 0.001,
                "savings_usd_per_1k_calls": 1.0,
                "equivalence_ci": [0.7, 1.0],
            },
            "equivalence": {"verdict": "equivalent", "repetitions": 2},
            "usage_old": {
                "calls": 2, "input_tokens": 10, "output_tokens": 20,
                "avg_latency_sec": 0.5, "unit_cost_usd": 0.002,
            },
            "usage_new": {
                "calls": 2, "input_tokens": 10, "output_tokens": 5,
                "avg_latency_sec": 0.1, "unit_cost_usd": 0.001,
            },
            "manifest": {"dataset_sha256": "abc"},
        }))

        markdown = to_markdown(report)

        self.assertIn("Proof-of-Savings Report", markdown)
        self.assertIn("Token usage", markdown)
        self.assertIn("demo", markdown)


if __name__ == "__main__":
    unittest.main()
