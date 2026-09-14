"""Тесты WORM-зеркала леджера (scripts/mirror_ledger.py).

Каждый гейт доказан красным: подделка, которую гейт обязан поймать,
временно подставляется, и ожидается именно отказ (SystemExit с нужным
кодом), а не «дружелюбное» продолжение. Философия та же, что у
фальсификационной батареи: гейт, который не был красным, — не гейт.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "mirror_ledger.py"

spec = importlib.util.spec_from_file_location("mirror_ledger", SCRIPT)
mirror = importlib.util.module_from_spec(spec)
sys.modules["mirror_ledger"] = mirror
spec.loader.exec_module(mirror)


def load_entries_from_text(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line.strip()]


class Gate1LocalChain(unittest.TestCase):
    """Гейт 1: битая локальная цепь — отказ с кодом 1."""

    def test_damaged_local_chain_refused(self) -> None:
        entries = [
            json.loads(line)
            for line in (REPO_ROOT / "receipts" / "registry.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]
        entries[1]["metadata"]["savings_ratio"] = 0.99  # подделка содержимого

        with mock.patch.object(mirror, "REGISTRY") as fake_path:
            fake_path.read_text = lambda *a, **k: "\n".join(
                json.dumps(e) for e in entries
            )
            with self.assertRaises(SystemExit) as ctx:
                mirror.local_chain_head()
            self.assertEqual(ctx.exception.code, 1)


class Gate2MirrorExtends(unittest.TestCase):
    """Гейт 2: расхождение истории — человек-алерт, код 2."""

    def _local_head(self) -> dict:
        return mirror.local_chain_head()

    def test_mirror_longer_than_local_alerts(self) -> None:
        local = self._local_head()
        longer = {"seq": local["seq"], "hash": local["hash"], "count": local["count"] + 1}
        with self.assertRaises(SystemExit) as ctx:
            mirror.gate_2_mirror_extends(local, longer)
        self.assertEqual(ctx.exception.code, 2)

    def test_diverged_head_alerts(self) -> None:
        local = self._local_head()
        # зеркало ведёт про существующую seq, но с чужим хешем
        forged = {"seq": local["seq"], "hash": "aa" * 32, "count": local["count"]}
        with self.assertRaises(SystemExit) as ctx:
            mirror.gate_2_mirror_extends(local, forged)
        self.assertEqual(ctx.exception.code, 2)

    def test_valid_prefix_passes(self) -> None:
        local = self._local_head()
        # префикс: голова зеркала = любая из локальных записей
        prefix = {"seq": 2, "hash": self._entry_hash_by_seq(2), "count": 2}
        mirror.gate_2_mirror_extends(local, prefix)  # не должен бросить
        mirror.gate_2_mirror_extends(local, None)  # первое зеркало — тоже ок

    def _entry_hash_by_seq(self, seq: int) -> str | None:
        for entry in mirror._load_entries(mirror.REGISTRY):
            if entry.get("seq") == seq:
                return entry["entry_hash"]
        return None


class Gate3OnlyTrustPaths(unittest.TestCase):
    """Гейт 3: в staging не должно быть ничего кроме trust-путей."""

    def test_unexpected_staged_path_refused(self) -> None:
        with mock.patch.object(
            mirror, "_git", return_value=mock.Mock(stdout="README.md\n")
        ):
            with self.assertRaises(SystemExit) as ctx:
                mirror.gate_3_only_trust_paths_staged()
            self.assertEqual(ctx.exception.code, 1)

    def test_trust_paths_pass(self) -> None:
        staged = "receipts/registry.jsonl\nreceipts/checkpoints.jsonl\nanchors/00f5f3a4a442423f8858ddf3999fa52c.json\n"
        with mock.patch.object(mirror, "_git", return_value=mock.Mock(stdout=staged)):
            mirror.gate_3_only_trust_paths_staged()  # не должен бросить


if __name__ == "__main__":
    unittest.main()
