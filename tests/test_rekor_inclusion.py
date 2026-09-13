"""Тесты проверки №9 rederive: RFC 6962 inclusion-proof записи Rekor.

Фикстура tests/fixtures/rekor_record1_entry.json — живой ответ публичного
Rekor (2026-09-13) на запись №1 SIA; тесты офлайновые: фолд считается
локально из фикстуры, сеть не нужна.

Формулы — порт transparency-dev/merkle proof/verify.go. Ключевой канал
подлога, закрытый этой проверкой: в шардированном инстансе у записи ДВА
индекса (виртуальный entry.logIndex и внутришардовый
inclusionProof.logIndex) — взаимная подмена ловится фолдом.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "rekor_record1_entry.json"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "verifier"))

from sia_verifier.rederive import _verify_rekor_inclusion  # noqa: E402


def _load() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class RekorInclusionProofTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entry = _load()

    def test_intact_proof_verifies(self) -> None:
        ok, detail, debug = _verify_rekor_inclusion(self.entry)

        self.assertTrue(ok, detail)
        self.assertTrue(debug["proof_root_match"])
        self.assertTrue(debug["checkpoint_root_match"])

    def test_tampered_proof_hash_rejected(self) -> None:
        bad = copy.deepcopy(self.entry)
        bad["verification"]["inclusionProof"]["hashes"][15] = "cc" * 32

        ok, _, _ = _verify_rekor_inclusion(bad)
        self.assertFalse(ok)

    def test_virtual_index_swap_rejected(self) -> None:
        # Подмена внутришардового индекса виртуальным (entry.logIndex) —
        # ровно та путаница, которую доказательство обязано не простить.
        bad = copy.deepcopy(self.entry)
        bad["verification"]["inclusionProof"]["logIndex"] = bad["logIndex"]

        ok, _, _ = _verify_rekor_inclusion(bad)
        self.assertFalse(ok)

    def test_forged_root_rejected(self) -> None:
        bad = copy.deepcopy(self.entry)
        bad["verification"]["inclusionProof"]["rootHash"] = "dd" * 32

        ok, _, _ = _verify_rekor_inclusion(bad)
        self.assertFalse(ok)

    def test_truncated_proof_rejected(self) -> None:
        bad = copy.deepcopy(self.entry)
        bad["verification"]["inclusionProof"]["hashes"] = \
            bad["verification"]["inclusionProof"]["hashes"][:-1]

        ok, _, _ = _verify_rekor_inclusion(bad)
        self.assertFalse(ok)

    def test_missing_fields_rejected(self) -> None:
        bad = copy.deepcopy(self.entry)
        del bad["verification"]["inclusionProof"]["hashes"]

        ok, _, _ = _verify_rekor_inclusion(bad)
        self.assertFalse(ok)

    def test_body_tamper_breaks_fold(self) -> None:
        # Подмена body меняет leaf-хеш и валит весь фолд — даже при
        # валидной с виду структуре proof.
        bad = copy.deepcopy(self.entry)
        import base64

        body = json.loads(base64.b64decode(bad["body"]))
        body["spec"]["data"]["hash"]["value"] = "ee" * 32
        bad["body"] = base64.b64encode(
            json.dumps(body).encode()
        ).decode()

        ok, _, _ = _verify_rekor_inclusion(bad)
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
