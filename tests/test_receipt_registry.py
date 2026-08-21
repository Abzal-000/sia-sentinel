from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sentinel.cryptographic_receipts import ReceiptGenerator, ReceiptVerifier
from sentinel.receipt_registry import ReceiptRegistry


class ReceiptRegistryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.storage_dir = str(Path(self._tmp.name) / "receipts")

        self.generator = ReceiptGenerator("registry-test-key")
        self.verifier = ReceiptVerifier(self.generator.get_public_key())
        self.registry = ReceiptRegistry(self.storage_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_receipt(self, name: str = "flow"):
        return self.generator.generate_receipt(
            evidence_id=f"evidence-{name}",
            code=f"# code for {name}",
            safety_approved=True,
            trust_level="JUNIOR",
            manifest={"flow_name": name},
        )

    def test_register_and_get(self) -> None:
        receipt = self._make_receipt("alpha")

        registry_id = self.registry.register(receipt, metadata={"flow_name": "alpha"})

        entry = self.registry.get(registry_id)

        self.assertIsNotNone(entry)
        self.assertEqual(entry["receipt"]["evidence_id"], "evidence-alpha")
        self.assertEqual(entry["metadata"]["flow_name"], "alpha")
        self.assertEqual(entry["registry_id"], registry_id)

    def test_get_unknown_returns_none(self) -> None:
        self.assertIsNone(self.registry.get("nonexistent"))

    def test_list_newest_first_with_total(self) -> None:
        self.registry.register(self._make_receipt("first"), metadata={"flow_name": "first"})
        self.registry.register(self._make_receipt("second"), metadata={"flow_name": "second"})

        summaries = self.registry.list_receipts()

        self.assertEqual(self.registry.count(), 2)
        self.assertEqual(len(summaries), 2)
        self.assertEqual(summaries[0]["metadata"]["flow_name"], "second")
        self.assertTrue(summaries[0]["has_manifest"])

    def test_verify_stored_valid_and_missing(self) -> None:
        registry_id = self.registry.register(self._make_receipt("verifiable"))

        self.assertTrue(self.registry.verify_stored(registry_id, self.verifier))
        self.assertIsNone(self.registry.verify_stored("missing", self.verifier))

    def test_tampered_entry_fails_verification(self) -> None:
        registry_id = self.registry.register(self._make_receipt("tamper-me"))

        registry_file = Path(self.storage_dir) / "registry.jsonl"
        entries = [
            json.loads(line)
            for line in registry_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries[0]["receipt"]["safety_approved"] = False

        registry_file.write_text(
            "\n".join(json.dumps(entry) for entry in entries) + "\n",
            encoding="utf-8",
        )

        self.assertFalse(self.registry.verify_stored(registry_id, self.verifier))

    def test_persistence_across_instances(self) -> None:
        receipt = self._make_receipt("persistent")
        registry_id = self.registry.register(receipt)

        reopened = ReceiptRegistry(self.storage_dir)

        self.assertEqual(reopened.count(), 1)
        self.assertIsNotNone(reopened.get(registry_id))
        self.assertTrue(reopened.verify_stored(registry_id, self.verifier))


class ReceiptChainTestCase(unittest.TestCase):
    """Хеш-цепочка: tamper-evidence для удаления/подмены/перестановки."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.storage_dir = str(Path(self._tmp.name) / "receipts")

        self.generator = ReceiptGenerator("chain-test-key")
        self.verifier = ReceiptVerifier(self.generator.get_public_key())
        self.registry = ReceiptRegistry(self.storage_dir)

        for name in ("one", "two", "three"):
            self.registry.register(self._make_receipt(name), metadata={"flow_name": name})

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_receipt(self, name: str):
        return self.generator.generate_receipt(
            evidence_id=f"evidence-{name}",
            code=f"# code for {name}",
            safety_approved=True,
            trust_level="JUNIOR",
        )

    def _rewrite(self, entries: list[dict]) -> None:
        registry_file = Path(self.storage_dir) / "registry.jsonl"
        registry_file.write_text(
            "\n".join(json.dumps(entry) for entry in entries) + "\n",
            encoding="utf-8",
        )

    def _entries(self) -> list[dict]:
        registry_file = Path(self.storage_dir) / "registry.jsonl"
        return [
            json.loads(line)
            for line in registry_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_chain_valid_after_registration(self) -> None:
        result = self.registry.verify_chain()

        self.assertTrue(result["valid"])
        self.assertEqual(result["entries"], 3)
        self.assertEqual(result["legacy_entries"], 0)

    def test_head_tracks_last_entry(self) -> None:
        head = self.registry.head()

        self.assertEqual(head["seq"], 3)
        self.assertEqual(head["entry_hash"], self._entries()[-1]["entry_hash"])

    def test_tampered_content_detected(self) -> None:
        entries = self._entries()
        entries[1]["receipt"]["safety_approved"] = False
        self._rewrite(entries)

        # Подмена в уже проверенном префиксе ловится полной проверкой
        result = self.registry.verify_chain(full=True)

        self.assertFalse(result["valid"])
        self.assertEqual(result["broken_at"], 2)
        self.assertIn("tampered", result["reason"])

    def test_removed_record_detected(self) -> None:
        entries = self._entries()
        del entries[0]
        self._rewrite(entries)

        result = self.registry.verify_chain(full=True)

        self.assertFalse(result["valid"])
        self.assertIn("prev_hash mismatch", result["reason"])

    def test_reordered_records_detected(self) -> None:
        entries = self._entries()
        entries[0], entries[1] = entries[1], entries[0]
        self._rewrite(entries)

        result = self.registry.verify_chain(full=True)

        self.assertFalse(result["valid"])

    def test_legacy_entries_still_verify(self) -> None:
        # Записи без seq/prev_hash/entry_hash (до введения цепочки)
        entries = self._entries()
        for entry in entries:
            entry.pop("seq", None)
            entry.pop("prev_hash", None)
            entry.pop("entry_hash", None)
        self._rewrite(entries)

        result = self.registry.verify_chain(full=True)

        self.assertTrue(result["valid"])
        self.assertEqual(result["legacy_entries"], 3)

    def test_checkpoint_signs_head(self) -> None:
        checkpoint = self.registry.create_checkpoint(self.generator)

        self.assertIsNotNone(checkpoint)
        self.assertEqual(checkpoint["seq"], 3)
        self.assertEqual(checkpoint["head_hash"], self.registry.head()["entry_hash"])
        self.assertTrue(self.registry.verify_checkpoint(checkpoint, self.verifier))

    def test_checkpoint_tamper_detected(self) -> None:
        checkpoint = self.registry.create_checkpoint(self.generator)
        checkpoint["head_hash"] = "f" * 64

        self.assertFalse(self.registry.verify_checkpoint(checkpoint, self.verifier))

    def test_checkpoint_on_empty_ledger_returns_none(self) -> None:
        empty = ReceiptRegistry(str(Path(self._tmp.name) / "empty"))

        self.assertIsNone(empty.create_checkpoint(self.generator))

    def test_checkpoint_persistence_and_listing(self) -> None:
        self.registry.create_checkpoint(self.generator)

        reopened = ReceiptRegistry(self.storage_dir)
        checkpoints = reopened.list_checkpoints()

        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(reopened.latest_checkpoint()["seq"], 3)


class CrashSafetyTestCase(unittest.TestCase):
    """D8: падение процесса посреди записи не повреждает цепочку."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.storage_dir = str(Path(self._tmp.name) / "receipts")

        self.generator = ReceiptGenerator("crash-test-key")
        self.verifier = ReceiptVerifier(self.generator.get_public_key())
        self.registry = ReceiptRegistry(self.storage_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_receipt(self, name: str):
        return self.generator.generate_receipt(
            evidence_id=f"evidence-{name}",
            code=f"# code for {name}",
            safety_approved=True,
            trust_level="JUNIOR",
        )

    def _registry_file(self) -> Path:
        return Path(self.storage_dir) / "registry.jsonl"

    def test_torn_trailing_line_is_dropped_on_read(self) -> None:
        self.registry.register(self._make_receipt("good"))

        # Имитация краха: неполная строка в конце файла
        with open(self._registry_file(), "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "prev_hash": "abc", "registry_id": "torn')

        # Чтение переживает битую последнюю строку
        self.assertEqual(self.registry.count(), 1)
        self.assertTrue(self.registry.verify_chain()["valid"])

    def test_append_after_crash_repairs_and_continues_chain(self) -> None:
        self.registry.register(self._make_receipt("before-crash"))

        with open(self._registry_file(), "a", encoding="utf-8") as handle:
            handle.write('{"seq": 2, "prev_hash": "abc", "registry_id": "torn')

        # Новая запись отбрасывает обрывок и продолжает цепочку
        self.registry.register(self._make_receipt("after-crash"))

        self.assertEqual(self.registry.count(), 2)

        result = self.registry.verify_chain()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries"], 2)

        # Вторая запись ссылается на хеш первой, а не на обрывок
        lines = [
            line for line in
            self._registry_file().read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        self.assertEqual(second["prev_hash"], first["entry_hash"])
        self.assertEqual(second["seq"], 2)

    def test_corrupt_middle_line_is_flagged_not_silently_dropped(self) -> None:
        for name in ("one", "two", "three"):
            self.registry.register(self._make_receipt(name))

        lines = self._registry_file().read_text(encoding="utf-8").splitlines()
        lines[1] = "NOT-JSON-CORRUPTED-MIDDLE"
        self._registry_file().write_text("\n".join(lines) + "\n", encoding="utf-8")

        with self.assertLogs("sentinel.receipt_registry", level="ERROR") as captured:
            entries = self.registry._load_entries()

        self.assertEqual(len(entries), 2)  # битая средняя строка пропущена
        self.assertTrue(
            any("middle of the ledger" in message for message in captured.output)
        )

        # Разрыв виден проверке цепочки
        result = self.registry.verify_chain()
        self.assertFalse(result["valid"])

    def test_checkpoint_file_survives_torn_write(self) -> None:
        self.registry.register(self._make_receipt("seed"))
        self.registry.create_checkpoint(self.generator)

        checkpoint_file = Path(self.storage_dir) / "checkpoints.jsonl"
        with open(checkpoint_file, "a", encoding="utf-8") as handle:
            handle.write('{"protocol": "trustchain-checkpoint/1", "seq": 99')

        checkpoints = self.registry.list_checkpoints()

        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(checkpoints[0]["seq"], 1)


class IncrementalVerificationTestCase(unittest.TestCase):
    """C2: инкрементальная верификация цепочки с кешем."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.storage_dir = str(Path(self._tmp.name) / "receipts")

        self.generator = ReceiptGenerator("incremental-test-key")
        self.registry = ReceiptRegistry(self.storage_dir)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _make_receipt(self, name: str):
        return self.generator.generate_receipt(
            evidence_id=f"evidence-{name}",
            code=f"# code for {name}",
            safety_approved=True,
            trust_level="JUNIOR",
        )

    def test_first_verify_is_full_second_is_incremental(self) -> None:
        self.registry.register(self._make_receipt("one"))

        first = self.registry.verify_chain()
        self.assertTrue(first["valid"])
        self.assertFalse(first["incremental"])  # первый вызов — полный

        self.registry.register(self._make_receipt("two"))

        second = self.registry.verify_chain()
        self.assertTrue(second["valid"])
        self.assertTrue(second["incremental"])  # повторный — инкрементальный
        self.assertEqual(second["entries"], 2)

    def test_incremental_detects_new_corrupt_entry(self) -> None:
        self.registry.register(self._make_receipt("good"))
        self.registry.verify_chain()  # прогреваем кеш

        # Новая запись с битым entry_hash ловится инкрементальной проверкой
        registry_file = Path(self.storage_dir) / "registry.jsonl"
        lines = registry_file.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["seq"] = 2
        entry["prev_hash"] = entry["entry_hash"]
        entry["entry_hash"] = "f" * 64
        lines.append(json.dumps(entry))
        registry_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = self.registry.verify_chain()

        self.assertFalse(result["valid"])
        self.assertTrue(result["incremental"])
        self.assertEqual(result["broken_at"], 2)

    def test_anchor_detects_prefix_tamper_without_full_flag(self) -> None:
        self.registry.register(self._make_receipt("one"))
        self.registry.register(self._make_receipt("two"))
        self.registry.verify_chain()  # кеш на seq=2

        # Подмена ПОСЛЕДНЕЙ кешированной записи: якорная проверка обязана
        # заметить несовпадение кешированного head_hash
        registry_file = Path(self.storage_dir) / "registry.jsonl"
        lines = registry_file.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[1])
        entry["receipt"]["safety_approved"] = False
        lines[1] = json.dumps(entry)
        registry_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = self.registry.verify_chain()

        self.assertFalse(result["valid"])
        self.assertIn("prefix tampered", result["reason"])

    def test_shrunk_ledger_detected(self) -> None:
        self.registry.register(self._make_receipt("one"))
        self.registry.register(self._make_receipt("two"))
        self.registry.verify_chain()  # кеш на seq=2

        # Удаление записи укорачивает журнал ниже кешированного префикса
        registry_file = Path(self.storage_dir) / "registry.jsonl"
        lines = registry_file.read_text(encoding="utf-8").splitlines()
        registry_file.write_text(lines[0] + "\n", encoding="utf-8")

        result = self.registry.verify_chain()

        self.assertFalse(result["valid"])
        self.assertIn("shrank", result["reason"])

    def test_full_flag_always_verifies_from_genesis(self) -> None:
        self.registry.register(self._make_receipt("one"))
        self.registry.verify_chain()  # прогреваем кеш

        full = self.registry.verify_chain(full=True)

        self.assertTrue(full["valid"])
        self.assertFalse(full["incremental"])

    def test_cache_survives_restart_as_full_verify(self) -> None:
        self.registry.register(self._make_receipt("one"))
        self.registry.verify_chain()

        # Новый экземпляр: кеш пуст, проверка снова полная
        reopened = ReceiptRegistry(self.storage_dir)
        result = reopened.verify_chain()

        self.assertTrue(result["valid"])
        self.assertFalse(result["incremental"])


if __name__ == "__main__":
    unittest.main()
