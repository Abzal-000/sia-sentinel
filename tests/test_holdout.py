"""П.8: holdout под контролем внешнего аудитора — тесты инструмента.

Сценарий полный: make (манифест подписан ключом аудитора, элементы в
секретном хранилище) → reveal (sha256 сходится) → verify (подпись + хеш
для третьей стороны). Плюс негативные: подмена элементов после манифеста,
пустой expect (таурология), чужой ключ.
"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "verifier"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from sia_verifier.holdout import (  # noqa: E402
    HOLDOUT_PROTOCOL,
    _manifest_body,
    dataset_sha256,
    main as holdout_main,
)


def _items(n: int = 3) -> list[dict[str, str]]:
    return [
        {"label": f"h{i}", "prompt": f"Q{i}", "expect_contains": f"ANSWER={i}"}
        for i in range(n)
    ]


class HoldoutEndToEndTestCase(unittest.TestCase):
    """make → reveal → verify на временных файлах."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        # Детерминированный тестовый ключ аудитора (64 hex)
        self.seed = "aa" * 32
        self.source = self.dir / "items.jsonl"
        self.source.write_text(
            "\n".join(json.dumps(i, ensure_ascii=False) for i in _items(3)),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make(self, note: str | None = None) -> None:
        args = [
            "make", "--source", str(self.source),
            "--out", str(self.dir / "manifest.json"),
            "--store", str(self.dir / "store.json"),
            "--key", self.seed,
        ]
        if note:
            args += ["--note", note]
        self.assertEqual(holdout_main(args), 0)

    def test_make_reveal_verify_cycle(self) -> None:
        self._make(note="record 2 candidate")
        manifest = json.loads((self.dir / "manifest.json").read_text(encoding="utf-8"))
        store = json.loads((self.dir / "store.json").read_text(encoding="utf-8"))

        # Манифест публичен и НЕ содержит элементов — оператор слеп
        self.assertEqual(manifest["protocol"], HOLDOUT_PROTOCOL)
        self.assertEqual(manifest["n"], 3)
        self.assertNotIn("items", manifest)
        self.assertEqual(
            manifest["dataset_sha256"], dataset_sha256(_items(3))
        )
        # Стор не утёк в манифест
        self.assertNotIn("items", json.dumps(manifest))

        # reveal: элементы извлекаются, хеш совпадает
        self.assertEqual(
            holdout_main([
                "reveal", "--store", str(self.dir / "store.json"),
                "--out", str(self.dir / "revealed.jsonl"),
            ]),
            0,
        )
        revealed = [
            json.loads(line)
            for line in (self.dir / "revealed.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(revealed), 3)

        # verify: подпись валидна и для третьей стороны, элементы соответствуют
        rc = holdout_main([
            "verify", "--manifest", str(self.dir / "manifest.json"),
            "--items", str(self.dir / "revealed.jsonl"),
        ])
        self.assertEqual(rc, 0)
        # store самосогласован
        self.assertEqual(store["manifest"]["dataset_sha256"], manifest["dataset_sha256"])

    def test_tampered_items_fail_verify(self) -> None:
        self._make()
        revealed = self.dir / "revealed.jsonl"
        revealed.write_text(
            json.dumps({"label": "x", "prompt": "OTHER", "expect_contains": "ANSWER=9"}) + "\n",
            encoding="utf-8",
        )
        rc = holdout_main([
            "verify", "--manifest", str(self.dir / "manifest.json"),
            "--items", str(revealed),
        ])
        self.assertEqual(rc, 1)

    def test_forged_manifest_signature_fails(self) -> None:
        self._make()
        manifest_path = self.dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        # Подпись чужим ключом (не тем, что в audit_pubkey)
        other = Ed25519PrivateKey.generate()
        manifest["signature"] = base64.b64encode(
            other.sign(_manifest_body(manifest))
        ).decode("ascii")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(holdout_main(["verify", "--manifest", str(manifest_path)]), 1)

    def test_item_without_expect_refused(self) -> None:
        bad = self.dir / "bad.jsonl"
        bad.write_text(
            json.dumps({"label": "x", "prompt": "Q", "expect_contains": ""}) + "\n",
            encoding="utf-8",
        )
        rc = holdout_main([
            "make", "--source", str(bad),
            "--out", str(self.dir / "m2.json"), "--store", str(self.dir / "s2.json"),
            "--key", self.seed,
        ])
        self.assertEqual(rc, 2)

    def test_manifest_body_covers_core_fields(self) -> None:
        """Подпись обязана покрывать n и dataset_sha256 — смена полей ломает её."""
        self._make()
        manifest_path = self.dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["n"] = 99  # «раздуть» holdout после подписи
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(holdout_main(["verify", "--manifest", str(manifest_path)]), 1)


if __name__ == "__main__":
    unittest.main()
