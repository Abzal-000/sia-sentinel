"""Тесты сторожа здоровья леджера scripts/ledger_health.py.

Сторож — операционный контур «запись закрыта?»: после каждой записи и в
проде по крону он обязан громко отличать здоровое состояние от больного
по КОДУ ВЫХОДА. Красные направления доказаны руками (2026-09-13:
подменённая запись цепи / устаревшее покрытие / поддельный чекпойнт /
пропавший якорь = exit 1 каждый); эти тесты запирают их навсегда.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sentinel.cryptographic_receipts import ReceiptGenerator  # noqa: E402
from sentinel.receipt_registry import ReceiptRegistry  # noqa: E402

HEALTH_SCRIPT = REPO_ROOT / "scripts" / "ledger_health.py"


def _build_healthy_ledger(dir_path: Path, key_material: str = "health-test-key") -> dict:
    """Здоровый леджер: запись → декларация ключа → чекпойнт → якорь."""
    receipts = dir_path / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    registry = ReceiptRegistry(str(receipts))
    generator = ReceiptGenerator(key_material)

    registry.register(
        generator.generate_receipt(
            evidence_id="health-check",
            code='{"report": "stub"}',
            safety_approved=True,
            trust_level="JUNIOR",
            manifest={"dataset_sha256": "a" * 64},
        ),
        metadata={"tenant_id": "sia", "savings_verified": True, "savings_ratio": 0.5},
    )
    registry.register_key_declaration(
        generator.kid, generator.get_public_key(), generator
    )
    checkpoint = registry.create_checkpoint(generator)
    anchors = dir_path / "anchors"
    anchors.mkdir(exist_ok=True)
    (anchors / f"{checkpoint['checkpoint_id']}.json").write_text(
        json.dumps(checkpoint), encoding="utf-8"
    )
    return {"receipts": receipts, "anchors": anchors, "checkpoint": checkpoint}


class LedgerHealthTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir_path = Path(self._tmp.name)
        _build_healthy_ledger(self.dir_path)
        self.env = {
            **os.environ,
            "RECEIPTS_DIR": str(self.dir_path / "receipts"),
            "ANCHORS_DIR": str(self.dir_path / "anchors"),
        }

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(HEALTH_SCRIPT)],
            capture_output=True, text=True, env=self.env, cwd=str(REPO_ROOT),
        )

    def test_healthy_ledger_exit_zero(self) -> None:
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for expected in ("chain: VALID", "coverage:", "merkle:"):
            self.assertIn(expected, result.stdout)

    def test_tampered_chain_entry_exit_one(self) -> None:
        registry_file = self.dir_path / "receipts" / "registry.jsonl"
        lines = registry_file.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["metadata"]["savings_ratio"] = 0.99
        lines[0] = json.dumps(entry)
        registry_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("INVALID", result.stdout)

    def test_uncovered_head_exit_one(self) -> None:
        # голова цепи растёт ПОСЛЕ чекпойнта — реконструкция состояния,
        # в котором реальная запись №2 прожила 6 дней молча.
        receipts = self.dir_path / "receipts"
        registry = ReceiptRegistry(str(receipts))
        generator = ReceiptGenerator("health-test-key")
        registry.register(
            generator.generate_receipt(
                evidence_id="health-check-2",
                code='{"report": "stub2"}',
                safety_approved=True,
                trust_level="JUNIOR",
            ),
            metadata={"tenant_id": "sia"},
        )

        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("GAP", result.stdout)

    def test_forged_checkpoint_exit_one(self) -> None:
        checkpoint_file = self.dir_path / "receipts" / "checkpoints.jsonl"
        checkpoints = [
            json.loads(line)
            for line in checkpoint_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        checkpoints[-1]["root_hash"] = "ff" * 32
        checkpoint_file.write_text(
            "\n".join(json.dumps(c) for c in checkpoints) + "\n", encoding="utf-8"
        )

        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("INVALID", result.stdout)

    def test_missing_anchor_exit_one(self) -> None:
        for anchor in (self.dir_path / "anchors").glob("*.json"):
            anchor.unlink()

        result = self._run()
        self.assertEqual(result.returncode, 1)
        self.assertIn("MISSING", result.stdout)


if __name__ == "__main__":
    unittest.main()
