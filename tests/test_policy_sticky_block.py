"""Регрессионные тесты «липкой» блокировки и обязательного human-review.

ДЫРЫ, которые закрывает этот файл
--------------------------------
1) DOWNGRADE БЛОКИРОВКИ (policy_engine). Правило с action=block выставляло
   recommendation="block", но финальное переопределение по risk_level могло
   ПОНИЗИТЬ его до "review" (если суммарный risk_score не дотянул до
   critical, но попал в high). Аналогично последующее правило warning/approve
   могло перекрыть block. Итог: политика запрещала изменение, а система
   разрешала его с пометкой «на ревью». Для контроля ИБ это тихая дыра.

2) ОБХОД require_human (webhook_handler + api /v1/verify-change). Условие было
   `recommendation != "block"`, поэтому изменение, помеченное require_human
   (recommendation == "review"), получало approved=True и проходило как
   проверенное — обязательная проверка человеком обходилась автоматически.

Политика безопасности: явный block нельзя ослабить ничем; require_human = пауза,
а не рекомендация.

Синтаксис условий policy_engine: "<field> <operator> <value>", например
"proposed_code contains 'os.system'".
"""
from __future__ import annotations

import unittest

from sentinel.policy_engine import Policy, PolicyEngine, PolicyRule

# Всегда истинное условие для предложенного кода ниже.
MATCH = "proposed_code contains 'rm -rf'"
NOMATCH = "proposed_code contains 'ZZZ_NEVER_PRESENT'"


class StickyBlockTestCase(unittest.TestCase):
    """Явная блокировка не понижается до review/approve."""

    def _engine(self, policies: list[Policy]) -> PolicyEngine:
        engine = PolicyEngine.__new__(PolicyEngine)  # не читаем YAML-каталог
        engine.policies = policies
        return engine

    def _assess(self, engine: PolicyEngine):
        return engine.assess_risk(
            agent_id="agent-1",
            target_path="src/api.py",
            current_code="x = 1",
            proposed_code="import os\nos.system('rm -rf /')",
        )

    def _policy(self, *rules: PolicyRule) -> Policy:
        return Policy(
            name="p", description="d", applies_to=["*"], rules=list(rules)
        )

    def test_block_survives_low_risk_level(self) -> None:
        """block остаётся block при низком risk_level (score < 60)."""
        engine = self._engine(
            [
                self._policy(
                    PolicyRule(
                        name="rm-rf", condition=MATCH, action="block",
                        risk_score_delta=10,
                    )
                )
            ]
        )
        result = self._assess(engine)
        self.assertIn("p:rm-rf", result.matched_rules)
        self.assertEqual(
            result.recommendation, "block", "block must never be downgraded"
        )

    def test_approve_rule_cannot_override_block(self) -> None:
        """Правило approve после block не отменяет блокировку."""
        engine = self._engine(
            [
                self._policy(
                    PolicyRule(
                        name="b", condition=MATCH, action="block",
                        risk_score_delta=0,
                    ),
                    PolicyRule(
                        name="a", condition=MATCH, action="approve",
                        risk_score_delta=0,
                    ),
                )
            ]
        )
        result = self._assess(engine)
        self.assertEqual(result.recommendation, "block")

    def test_require_human_does_not_downgrade_block(self) -> None:
        """require_human не превращает block в review."""
        engine = self._engine(
            [
                self._policy(
                    PolicyRule(
                        name="b", condition=MATCH, action="block",
                        risk_score_delta=0,
                    ),
                    PolicyRule(
                        name="h", condition=MATCH, action="require_human",
                        risk_score_delta=0,
                    ),
                )
            ]
        )
        result = self._assess(engine)
        self.assertEqual(result.recommendation, "block")
        self.assertTrue(result.requires_human_review)

    def test_high_risk_level_does_not_downgrade_existing_block(self) -> None:
        """risk_level=high не превращает явный block в review."""
        engine = self._engine(
            [
                self._policy(
                    PolicyRule(
                        name="b", condition=MATCH, action="block",
                        risk_score_delta=60,
                    )
                )
            ]
        )
        result = self._assess(engine)
        self.assertEqual(result.risk_level, "high")
        self.assertEqual(
            result.recommendation, "block",
            "high risk level must not downgrade an explicit block",
        )

    def test_no_match_still_approves(self) -> None:
        """Без сработавших правил поведение не изменилось."""
        engine = self._engine(
            [
                self._policy(
                    PolicyRule(
                        name="never", condition=NOMATCH, action="block",
                        risk_score_delta=50,
                    )
                )
            ]
        )
        result = self._assess(engine)
        self.assertEqual(result.recommendation, "approve")
        self.assertEqual(result.matched_rules, [])

    def test_require_human_alone_yields_review_and_flag(self) -> None:
        """Один require_human -> review + флаг (для ручного подтверждения)."""
        engine = self._engine(
            [
                self._policy(
                    PolicyRule(
                        name="h", condition=MATCH, action="require_human",
                        risk_score_delta=0,
                    )
                )
            ]
        )
        result = self._assess(engine)
        self.assertEqual(result.recommendation, "review")
        self.assertTrue(result.requires_human_review)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
