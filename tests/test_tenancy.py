from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.tenancy import (
    DEFAULT_TENANT_ID,
    TenantManager,
    UsageMeter,
    resolve_tenant_id,
)


class TenantManagerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tenants_file = str(Path(self._tmp.name) / "tenants.json")
        self.manager = TenantManager(self.tenants_file)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_default_tenant_created(self) -> None:
        tenant = self.manager.get(DEFAULT_TENANT_ID)

        self.assertIsNotNone(tenant)
        self.assertEqual(tenant.plan, "free")

    def test_create_and_get(self) -> None:
        tenant = self.manager.create(name="Acme Corp", tenant_id="acme", plan="pro")

        self.assertEqual(tenant.tenant_id, "acme")
        self.assertEqual(self.manager.get("acme").name, "Acme Corp")

    def test_create_generates_id_when_missing(self) -> None:
        tenant = self.manager.create(name="No Id Corp")

        self.assertTrue(tenant.tenant_id)
        self.assertIsNotNone(self.manager.get(tenant.tenant_id))

    def test_invalid_tenant_id_rejected(self) -> None:
        for bad_id in ("UPPER", "-leading", "x", "has space", "a" * 100):
            with self.assertRaises(ValueError):
                self.manager.create(name="Bad", tenant_id=bad_id)

    def test_duplicate_tenant_rejected(self) -> None:
        self.manager.create(name="First", tenant_id="dup")

        with self.assertRaises(ValueError):
            self.manager.create(name="Second", tenant_id="dup")

    def test_list_includes_all(self) -> None:
        self.manager.create(name="A", tenant_id="ta")
        self.manager.create(name="B", tenant_id="tb")

        ids = {t.tenant_id for t in self.manager.list()}

        self.assertEqual(ids, {DEFAULT_TENANT_ID, "ta", "tb"})

    def test_persistence_across_instances(self) -> None:
        self.manager.create(name="Persisted", tenant_id="persisted", plan="pro")

        reopened = TenantManager(self.tenants_file)

        self.assertEqual(reopened.get("persisted").name, "Persisted")
        self.assertEqual(reopened.get("persisted").plan, "pro")


class UsageMeterTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.usage_file = str(Path(self._tmp.name) / "usage.jsonl")
        self.meter = UsageMeter(self.usage_file)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_record_and_summary(self) -> None:
        self.meter.record("acme", kind="llm_flow", mode="simulated",
                          savings_verified=True, savings_usd_per_1k=0.05)
        self.meter.record("acme", kind="optimize", mode="live",
                          savings_verified=True, savings_usd_per_1k=0.04)
        self.meter.record("acme", kind="llm_flow", mode="live",
                          savings_verified=False)

        summary = self.meter.summary("acme")

        self.assertEqual(summary["total_events"], 3)
        self.assertEqual(summary["by_kind"], {"llm_flow": 2, "optimize": 1})
        self.assertEqual(summary["by_mode"], {"simulated": 1, "live": 2})
        self.assertEqual(summary["verified_savings_count"], 2)

    def test_summary_filters_by_tenant(self) -> None:
        self.meter.record("acme", kind="llm_flow")
        self.meter.record("globex", kind="llm_flow")
        self.meter.record("globex", kind="optimize")

        self.assertEqual(self.meter.summary("acme")["total_events"], 1)
        self.assertEqual(self.meter.summary("globex")["total_events"], 2)

    def test_empty_tenant_summary(self) -> None:
        summary = self.meter.summary("nobody")

        self.assertEqual(summary["total_events"], 0)
        self.assertEqual(summary["by_kind"], {})

    def test_persistence_across_instances(self) -> None:
        self.meter.record("acme", kind="llm_flow")

        reopened = UsageMeter(self.usage_file)

        self.assertEqual(reopened.summary("acme")["total_events"], 1)


class ResolveTenantIdTestCase(unittest.TestCase):
    def test_none_and_empty_resolve_to_default(self) -> None:
        self.assertEqual(resolve_tenant_id(None), DEFAULT_TENANT_ID)
        self.assertEqual(resolve_tenant_id(""), DEFAULT_TENANT_ID)

    def test_explicit_id_preserved(self) -> None:
        self.assertEqual(resolve_tenant_id("acme"), "acme")


if __name__ == "__main__":
    unittest.main()
