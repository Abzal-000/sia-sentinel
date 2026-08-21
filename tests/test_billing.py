from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sentinel.billing import (
    CATEGORY_AUDITS,
    CATEGORY_OPTIMIZATIONS,
    PLANS,
    BillingEngine,
    Invoice,
    InvoiceLine,
    category_for_kind,
    current_period,
    parse_period,
)
from sentinel.tenancy import TenantManager, UsageMeter


class BillingHelpersTestCase(unittest.TestCase):
    """Чистые функции: категории, периоды."""

    def test_category_for_kind(self) -> None:
        self.assertEqual(category_for_kind("optimize"), CATEGORY_OPTIMIZATIONS)
        self.assertEqual(category_for_kind("code"), CATEGORY_AUDITS)
        self.assertEqual(category_for_kind("llm_flow"), CATEGORY_AUDITS)
        self.assertEqual(category_for_kind(None), CATEGORY_AUDITS)

    def test_current_period_format(self) -> None:
        period = current_period()
        year, month = parse_period(period)
        self.assertGreaterEqual(year, 2026)
        self.assertTrue(1 <= month <= 12)

    def test_parse_period_valid(self) -> None:
        self.assertEqual(parse_period("2026-08"), (2026, 8))
        self.assertEqual(parse_period("2026-12"), (2026, 12))

    def test_parse_period_invalid(self) -> None:
        for bad in ("2026", "2026-13", "2026-00", "abc", "26-08", None, 202608):
            with self.assertRaises(ValueError):
                parse_period(bad)

    def test_plans_catalog_shape(self) -> None:
        self.assertEqual(set(PLANS), {"free", "pro", "enterprise"})

        free = PLANS["free"]
        self.assertEqual(free.monthly_price_usd, 0.0)
        self.assertIsNone(free.overage_usd[CATEGORY_AUDITS])

        enterprise = PLANS["enterprise"]
        self.assertIsNone(enterprise.included[CATEGORY_AUDITS])


class BillingEngineTestCase(unittest.TestCase):
    """Квоты, смена плана, инвойсы — на изолированных временных файлах."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)

        self.tenants = TenantManager(str(base / "tenants.json"))
        self.usage = UsageMeter(str(base / "usage.jsonl"))
        self.engine = BillingEngine(
            self.tenants, self.usage, invoices_file=str(base / "invoices.json")
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _record(self, tenant_id: str, kind: str, count: int = 1) -> None:
        for _ in range(count):
            self.usage.record(tenant_id=tenant_id, kind=kind)

    # --- Квоты ---

    def test_free_plan_allows_within_quota(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")
        self._record("acme", "llm_flow", 3)

        check = self.engine.check_quota("acme", "llm_flow")

        self.assertTrue(check.allowed)
        self.assertEqual(check.used, 3)
        self.assertEqual(check.limit, 10)

    def test_free_plan_blocks_at_quota(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")
        self._record("acme", "llm_flow", 10)

        check = self.engine.check_quota("acme", "llm_flow")

        self.assertFalse(check.allowed)
        self.assertIn("quota exceeded", check.reason)
        self.assertIn("Upgrade", check.reason)

    def test_free_plan_optimize_quota_separate(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")
        self._record("acme", "optimize", 1)

        # Оптимизации исчерпаны, но аудиты ещё доступны
        self.assertFalse(self.engine.check_quota("acme", "optimize").allowed)
        self.assertTrue(self.engine.check_quota("acme", "llm_flow").allowed)

    def test_pro_plan_allows_overage(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")
        self._record("acme", "llm_flow", 500)

        check = self.engine.check_quota("acme", "llm_flow")

        self.assertTrue(check.allowed)
        self.assertIn("overage", check.reason)

    def test_enterprise_plan_unlimited(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="enterprise")
        self._record("acme", "llm_flow", 50)

        check = self.engine.check_quota("acme", "llm_flow")

        self.assertTrue(check.allowed)
        self.assertIsNone(check.limit)

    def test_unknown_tenant_gets_free_plan(self) -> None:
        plan = self.engine.get_plan("ghost-tenant")
        self.assertEqual(plan.name, "free")

    def test_unknown_plan_name_falls_back_to_free(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="gold")

        plan = self.engine.get_plan("acme")
        self.assertEqual(plan.name, "free")

    def test_quota_ignores_other_tenants_usage(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")
        self.tenants.create(name="Globex", tenant_id="globex", plan="free")
        self._record("globex", "llm_flow", 10)

        self.assertTrue(self.engine.check_quota("acme", "llm_flow").allowed)

    def test_quota_ignores_previous_month(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")

        # События прошлого месяца не должны влиять на текущую квоту
        year, month = parse_period(current_period())
        prev_month, prev_year = (month - 1, year) if month > 1 else (12, year - 1)
        prefix = f"{prev_year:04d}-{prev_month:02d}"

        for i in range(10):
            self.usage.record(tenant_id="acme", kind="llm_flow")
            # Подменяем дату события на прошлый месяц
            self._rewrite_last_event_timestamp(prefix + "-15T00:00:00+00:00")

        check = self.engine.check_quota("acme", "llm_flow")
        self.assertTrue(check.allowed)
        self.assertEqual(check.used, 0)

    def _rewrite_last_event_timestamp(self, recorded_at: str) -> None:
        import json

        lines = self.usage.usage_file.read_text(encoding="utf-8").strip().splitlines()
        event = json.loads(lines[-1])
        event["recorded_at"] = recorded_at
        lines[-1] = json.dumps(event)
        self.usage.usage_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # --- Смена плана ---

    def test_set_plan_changes_quota(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")
        self._record("acme", "llm_flow", 10)

        self.assertFalse(self.engine.check_quota("acme", "llm_flow").allowed)

        tenant = self.engine.set_plan("acme", "pro")
        self.assertEqual(tenant.plan, "pro")
        self.assertTrue(self.engine.check_quota("acme", "llm_flow").allowed)

    def test_set_plan_unknown_plan_raises(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")

        with self.assertRaises(ValueError):
            self.engine.set_plan("acme", "platinum")

    def test_set_plan_unknown_tenant_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.engine.set_plan("ghost", "pro")

    # --- Инвойсы ---

    def test_invoice_free_plan_zero(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="free")
        self._record("acme", "llm_flow", 3)

        invoice = self.engine.issue_invoice("acme")

        self.assertEqual(invoice.total_usd, 0.0)
        self.assertEqual(invoice.lines, [])
        self.assertEqual(invoice.status, "open")

    def test_invoice_pro_plan_subscription_only(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")
        self._record("acme", "llm_flow", 100)

        invoice = self.engine.issue_invoice("acme")

        self.assertEqual(invoice.total_usd, 99.0)
        self.assertEqual(len(invoice.lines), 1)
        self.assertIn("Pro plan subscription", invoice.lines[0].description)

    def test_invoice_pro_plan_with_overage(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")
        self._record("acme", "llm_flow", 510)  # 10 сверх лимита 500
        self._record("acme", "optimize", 52)  # 2 сверх лимита 50

        invoice = self.engine.issue_invoice("acme")

        # 99 + 10*0.25 + 2*2.0 = 105.5
        self.assertEqual(invoice.total_usd, 105.5)
        self.assertEqual(len(invoice.lines), 3)

    def test_invoice_idempotent_per_tenant_period(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")

        first = self.engine.issue_invoice("acme")
        second = self.engine.issue_invoice("acme")

        self.assertEqual(first.invoice_id, second.invoice_id)
        self.assertEqual(len(self.engine.list_invoices("acme")), 1)

    def test_invoice_explicit_period(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")

        invoice = self.engine.issue_invoice("acme", "2026-07")

        self.assertEqual(invoice.period, "2026-07")
        self.assertEqual(invoice.total_usd, 99.0)

    def test_invoice_invalid_period_raises(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")

        with self.assertRaises(ValueError):
            self.engine.issue_invoice("acme", "2026-13")

    def test_invoice_tenant_isolation(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")
        self.tenants.create(name="Globex", tenant_id="globex", plan="pro")

        acme_invoice = self.engine.issue_invoice("acme")
        self.engine.issue_invoice("globex")

        # Acme видит свой инвойс, чужой — нет
        self.assertIsNotNone(self.engine.get_invoice(acme_invoice.invoice_id, "acme"))
        self.assertIsNone(self.engine.get_invoice(acme_invoice.invoice_id, "globex"))

        # Без тенанта — видно всё (админский доступ)
        self.assertEqual(len(self.engine.list_invoices()), 2)
        self.assertEqual(len(self.engine.list_invoices("acme")), 1)

    def test_invoices_persist_across_instances(self) -> None:
        self.tenants.create(name="Acme", tenant_id="acme", plan="pro")
        invoice = self.engine.issue_invoice("acme")

        # «Рестарт»: новый инстанс читает invoices.json
        reopened = BillingEngine(
            self.tenants, self.usage, invoices_file=str(self.engine.invoices_file)
        )

        restored = reopened.get_invoice(invoice.invoice_id)
        self.assertIsNotNone(restored)
        self.assertEqual(restored.total_usd, 99.0)
        self.assertEqual(restored.tenant_id, "acme")

    def test_invoice_line_rounding(self) -> None:
        line = InvoiceLine(description="x", quantity=3, unit_price_usd=0.333)
        self.assertEqual(line.amount_usd, 1.0)

        invoice = Invoice(
            invoice_id="inv-test",
            tenant_id="acme",
            plan="pro",
            period="2026-08",
            lines=[line],
            issued_at="2026-08-19T00:00:00+00:00",
        )
        self.assertEqual(invoice.total_usd, 1.0)


if __name__ == "__main__":
    unittest.main()
