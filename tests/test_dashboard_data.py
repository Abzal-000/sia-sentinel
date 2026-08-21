from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import pandas as pd

from sia.dashboard_data import (
    calculate_kpis,
    events_to_dataframe,
    get_task_summary,
    get_trust_level_history,
    load_events,
)


class DashboardDataTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.log_dir = Path(self._tmp.name)
        self.events_path = self.log_dir / "events.jsonl"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_events(self, events: list[dict]) -> None:
        with open(self.events_path, "w", encoding="utf-8") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

    def test_load_events_empty(self) -> None:
        events = load_events(str(self.log_dir))
        self.assertEqual(events, [])

    def test_load_events_with_data(self) -> None:
        self._write_events([{"event_type": "task_received", "payload": {}}])
        events = load_events(str(self.log_dir))
        self.assertEqual(len(events), 1)

    def test_events_to_dataframe(self) -> None:
        events = [
            {"timestamp": 1000, "event_id": "1", "event_type": "task_received", "payload": {}},
            {"timestamp": 2000, "event_id": "2", "event_type": "evaluation_result", "payload": {}},
        ]
        df = events_to_dataframe(events)
        self.assertEqual(len(df), 2)
        self.assertIn("datetime", df.columns)

    def test_calculate_kpis_empty(self) -> None:
        df = pd.DataFrame()
        kpis = calculate_kpis(df)
        self.assertEqual(kpis["total_tasks"], 0)

    def test_calculate_kpis_with_data(self) -> None:
        events = [
            {"timestamp": 1, "event_type": "task_received", "payload": {"task_id": "t1"}},
            {
                "timestamp": 2,
                "event_type": "evaluation_result",
                "payload": {
                    "task_id": "t1",
                    "approved": True,
                    "safety_score": 0.9,
                    "performance_gain": 0.25,
                },
            },
        ]
        df = events_to_dataframe(events)
        kpis = calculate_kpis(df)
        self.assertEqual(kpis["total_tasks"], 1)
        self.assertEqual(kpis["approved_tasks"], 1)
        self.assertAlmostEqual(kpis["avg_safety_score"], 0.9)
        self.assertAlmostEqual(kpis["avg_performance_gain"], 0.25)

    def test_get_task_summary(self) -> None:
        events = [
            {"timestamp": 1, "event_type": "task_received", "payload": {"task_id": "t1", "description": "test"}},
            {
                "timestamp": 2,
                "event_type": "evaluation_result",
                "payload": {"task_id": "t1", "approved": True},
            },
        ]
        df = events_to_dataframe(events)
        summary = get_task_summary(df)
        self.assertEqual(len(summary), 1)
        self.assertEqual(summary.iloc[0]["status"], "approved")

    def test_get_trust_level_history(self) -> None:
        events = [
            {
                "timestamp": 1,
                "event_type": "trust_updated_after_success",
                "payload": {"level": "INTERN"},
            },
        ]
        df = events_to_dataframe(events)
        history = get_trust_level_history(df)
        self.assertEqual(len(history), 1)
        self.assertEqual(history.iloc[0]["level"], "INTERN")

    def test_load_events_lazy_window(self) -> None:
        events = [
            {"event_type": "e", "payload": {"n": i}}
            for i in range(10)
        ]
        self._write_events(events)

        # Newest 3 events, chronological order
        window = load_events(str(self.log_dir), limit=3)
        self.assertEqual([e["payload"]["n"] for e in window], [7, 8, 9])

        # Skipping 2 older ones narrows the window
        window = load_events(str(self.log_dir), limit=3, offset=2)
        self.assertEqual([e["payload"]["n"] for e in window], [5, 6, 7])

        # Offset beyond the log returns nothing
        window = load_events(str(self.log_dir), limit=3, offset=50)
        self.assertEqual(window, [])

        # No limit -> everything
        window = load_events(str(self.log_dir))
        self.assertEqual(len(window), 10)

    def test_calculate_kpis_overall_efficiency_score(self) -> None:
        events = [
            {"timestamp": 1, "event_type": "task_received", "payload": {"task_id": "t1"}},
            {
                "timestamp": 2,
                "event_type": "evaluation_result",
                "payload": {
                    "task_id": "t1",
                    "approved": True,
                    "overall_efficiency_score": 0.75,
                },
            },
        ]
        df = events_to_dataframe(events)
        kpis = calculate_kpis(df)
        self.assertAlmostEqual(kpis["avg_overall_efficiency_score"], 0.75)

    def test_build_agent_graph_dot(self) -> None:
        from sia.dashboard_data import build_agent_graph_dot

        events = [
            {"event_type": "task_received", "payload": {"task_id": "t1"}},
            {"event_type": "trust_decision", "payload": {"task_id": "t1", "allowed": True}},
            {"event_type": "change_proposed", "payload": {"task_id": "t1", "new_code": "x = 1"}},
            {"event_type": "safety_check", "payload": {"task_id": "t1", "approved": False}},
            {"event_type": "evaluation_result", "payload": {"task_id": "t1", "approved": False}},
        ]
        df = events_to_dataframe(events)
        dot = build_agent_graph_dot(df)
        self.assertIn("digraph agent_pipeline", dot)
        self.assertIn("Trust Level Manager", dot)
        self.assertIn("Constitutional AI", dot)
        self.assertIn("->", dot)

    def test_build_agent_graph_dot_multi_agent(self) -> None:
        from sia.dashboard_data import build_agent_graph_dot

        events = [
            {"event_type": "task_received", "payload": {"task_id": "t2"}},
            {"event_type": "generator_agent", "payload": {"task_id": "t2", "success": True}},
            {"event_type": "security_agent", "payload": {"task_id": "t2", "success": True}},
            {"event_type": "test_agent", "payload": {"task_id": "t2", "success": True}},
            {"event_type": "refactor_agent", "payload": {"task_id": "t2", "success": True}},
            {"event_type": "evaluation_result", "payload": {"task_id": "t2", "approved": True}},
        ]
        df = events_to_dataframe(events)
        dot = build_agent_graph_dot(df, task_id="t2")
        self.assertIn("GeneratorAgent", dot)
        self.assertIn("RefactorAgent", dot)
        self.assertNotIn("Code Agent", dot)

    def test_build_ast_dot(self) -> None:
        from sia.dashboard_data import build_ast_dot

        code = "def add(a, b):\n    return a + b\n"
        dot = build_ast_dot(code)
        self.assertIn("digraph ast", dot)
        self.assertIn("FunctionDef" + "\\n" + "add", dot)
        self.assertIn("->", dot)

        broken = build_ast_dot("def broken(:")
        self.assertIn("синтаксическая ошибка", broken)

    def test_get_change_proposals(self) -> None:
        from sia.dashboard_data import get_change_proposals

        events = [
            {
                "event_type": "change_proposed",
                "payload": {"task_id": "t1", "model_name": "test-model", "new_code": "x = 1"},
            },
        ]
        df = events_to_dataframe(events)
        proposals = get_change_proposals(df)
        self.assertEqual(len(proposals), 1)
        self.assertEqual(proposals[0]["model_name"], "test-model")
        self.assertEqual(proposals[0]["new_code"], "x = 1")
