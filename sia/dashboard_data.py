from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import pandas as pd


def load_events(
    log_dir: str = "logs",
    limit: Optional[int] = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Load events from the JSONL log.

    Without ``limit`` every event is parsed. With ``limit`` only the newest
    ``limit`` events (skipping ``offset`` older ones) are decoded, so the
    dashboard can lazily load history without parsing the whole file.
    Events are returned in chronological order.
    """
    events_path = Path(log_dir) / "events.jsonl"

    if not events_path.exists():
        return []

    with open(events_path, "r", encoding="utf-8") as f:
        lines = [line for line in (raw.strip() for raw in f) if line]

    if limit is not None:
        window_start = max(len(lines) - offset - limit, 0)
        window_end = len(lines) - offset if offset else len(lines)
        lines = lines[window_start:window_end]

    events: list[dict[str, Any]] = []

    for line in lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return events


def load_traces(log_dir: str = "logs") -> list[dict[str, Any]]:
    traces_path = Path(log_dir) / "traces.jsonl"

    if not traces_path.exists():
        return []

    traces: list[dict[str, Any]] = []

    with open(traces_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                traces.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return traces


def events_to_dataframe(events: list[dict[str, Any]]) -> pd.DataFrame:
    if not events:
        return pd.DataFrame(columns=["timestamp", "event_id", "event_type", "payload"])

    df = pd.DataFrame(events)

    if "timestamp" in df.columns:
        df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")

    return df


def traces_to_dataframe(traces: list[dict[str, Any]]) -> pd.DataFrame:
    if not traces:
        return pd.DataFrame(columns=["name", "trace_id", "span_id", "duration_ms", "attributes"])

    records = []
    for span in traces:
        ctx = span.get("context", {})
        start = span.get("start_time", "")
        end = span.get("end_time", "")

        duration_ms = 0.0
        if start and end:
            try:
                from datetime import datetime
                fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
                t_start = datetime.strptime(start, fmt)
                t_end = datetime.strptime(end, fmt)
                duration_ms = (t_end - t_start).total_seconds() * 1000
            except (ValueError, TypeError):
                duration_ms = 0.0

        records.append({
            "name": span.get("name", ""),
            "trace_id": ctx.get("trace_id", ""),
            "span_id": ctx.get("span_id", ""),
            "parent_id": span.get("parent_id"),
            "start_time": start,
            "end_time": end,
            "duration_ms": duration_ms,
            "attributes": span.get("attributes", {}),
        })

    return pd.DataFrame(records)


def calculate_kpis(df: pd.DataFrame) -> dict[str, Any]:
    if df.empty:
        return {
            "total_tasks": 0,
            "approved_tasks": 0,
            "rejected_tasks": 0,
            "avg_safety_score": None,
            "avg_performance_gain": None,
            "avg_overall_efficiency_score": None,
        }

    task_received = df[df["event_type"] == "task_received"]
    evaluation_results = df[df["event_type"] == "evaluation_result"]

    total_tasks = len(task_received)

    approved = 0
    rejected = 0
    safety_scores: list[float] = []
    performance_gains: list[float] = []
    overall_scores: list[float] = []
    verified_savings_usd: list[float] = []

    for _, row in evaluation_results.iterrows():
        payload = row.get("payload", {})

        if payload.get("approved"):
            approved += 1
        else:
            rejected += 1

        if payload.get("safety_score") is not None:
            safety_scores.append(float(payload["safety_score"]))

        if payload.get("performance_gain") is not None:
            performance_gains.append(float(payload["performance_gain"]))

        if payload.get("overall_efficiency_score") is not None:
            overall_scores.append(float(payload["overall_efficiency_score"]))

        if payload.get("cost_savings_usd") is not None:
            verified_savings_usd.append(float(payload["cost_savings_usd"]))

    avg_safety = sum(safety_scores) / len(safety_scores) if safety_scores else None
    avg_perf = sum(performance_gains) / len(performance_gains) if performance_gains else None
    avg_overall = sum(overall_scores) / len(overall_scores) if overall_scores else None
    total_savings = sum(verified_savings_usd) if verified_savings_usd else None

    return {
        "total_tasks": total_tasks,
        "approved_tasks": approved,
        "rejected_tasks": rejected,
        "avg_safety_score": avg_safety,
        "avg_performance_gain": avg_perf,
        "avg_overall_efficiency_score": avg_overall,
        "total_verified_savings_usd": total_savings,
    }


def get_task_summary(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    tasks: dict[str, dict[str, Any]] = {}

    for _, row in df.iterrows():
        event_type = row.get("event_type")
        payload = row.get("payload", {})

        if event_type == "task_received":
            task_id = payload.get("task_id")
            if task_id:
                tasks[task_id] = {
                    "task_id": task_id,
                    "description": payload.get("description", ""),
                    "target_path": payload.get("target_path", ""),
                    "status": "started",
                    "approved": None,
                    "performance_gain": None,
                    "safety_score": None,
                    "overall_efficiency_score": None,
                    "cost_savings_usd": None,
                }

        elif event_type == "evaluation_result":
            task_id = payload.get("task_id")
            if task_id and task_id in tasks:
                tasks[task_id]["approved"] = payload.get("approved")
                tasks[task_id]["performance_gain"] = payload.get("performance_gain")
                tasks[task_id]["safety_score"] = payload.get("safety_score")
                tasks[task_id]["overall_efficiency_score"] = payload.get("overall_efficiency_score")
                tasks[task_id]["cost_savings_usd"] = payload.get("cost_savings_usd")
                tasks[task_id]["status"] = "approved" if payload.get("approved") else "rejected"

        elif event_type == "task_denied":
            task_id = payload.get("task_id")
            if task_id and task_id in tasks:
                tasks[task_id]["status"] = "denied"

    return pd.DataFrame(list(tasks.values()))


def get_change_proposals(df: pd.DataFrame) -> list[dict[str, Any]]:
    """Собирает предложения кода (для визуализации AST)."""
    if df.empty:
        return []

    proposals: list[dict[str, Any]] = []

    for _, row in df[df["event_type"] == "change_proposed"].iterrows():
        payload = row.get("payload", {})
        proposals.append({
            "task_id": payload.get("task_id", ""),
            "model_name": payload.get("model_name", ""),
            "new_code": payload.get("new_code", ""),
        })

    return proposals


def build_agent_graph_dot(df: pd.DataFrame, task_id: Optional[str] = None) -> str:
    """Строит dot-граф пайплайна агента со статусами этапов последней задачи."""
    if df.empty:
        return "digraph agent { node [shape=box]; \"нет данных\"; }"

    task_events = df[df["event_type"] == "task_received"]

    if task_id is None and not task_events.empty:
        task_id = task_events.iloc[-1].get("payload", {}).get("task_id")

    task_df = df
    if task_id is not None:
        mask = df["payload"].apply(lambda payload: payload.get("task_id") == task_id)
        task_df = df[mask.fillna(False)] if hasattr(mask, "fillna") else df

    def _last_event(event_type: str) -> Optional[dict[str, Any]]:
        events = task_df[task_df["event_type"] == event_type]
        if events.empty:
            return None
        payload = events.iloc[-1].get("payload", {})
        return payload if isinstance(payload, dict) else None

    def _last_agent_event(agent_event: str) -> Optional[dict[str, Any]]:
        events = task_df[task_df["event_type"] == agent_event]
        if events.empty:
            return None
        payload = events.iloc[-1].get("payload", {})
        return payload if isinstance(payload, dict) else None

    trust = _last_event("trust_decision")
    change = _last_event("change_proposed")
    generator = _last_agent_event("generator_agent")
    security = _last_agent_event("security_agent")
    test_agent = _last_agent_event("test_agent")
    refactor = _last_agent_event("refactor_agent")
    safety = _last_event("safety_check")
    sandbox = _last_event("sandbox_execution")
    evaluation = _last_event("evaluation_result")

    def _node_status(value: Optional[bool]) -> str:
        if value is None:
            return "#9e9e9e"
        return "#2e7d32" if value else "#c62828"

    stages: list[tuple[str, str, str]] = [
        ("trust", "Trust Level Manager", _node_status(trust.get("allowed") if trust else None)),
    ]

    if generator is not None:
        stages.append(("generator", "GeneratorAgent", _node_status(generator.get("success"))))
        stages.append(("security_agent", "SecurityAgent", _node_status(security.get("success") if security else None)))
        stages.append(("test_agent", "TestAgent", _node_status(test_agent.get("success") if test_agent else None)))
        stages.append(("refactor", "RefactorAgent", _node_status(refactor.get("success") if refactor else None)))
    else:
        stages.append(("generation", "Code Agent", _node_status(change is not None)))

    stages.append(("safety", "Constitutional AI", _node_status(safety.get("approved") if safety else None)))
    stages.append(("sandbox", "Sandbox Executor", _node_status(sandbox.get("success") if sandbox else None)))
    stages.append(("evaluation", "Evaluation Engine", _node_status(evaluation.get("approved") if evaluation else None)))
    stages.append(("trust_update", "Обновление доверия", _node_status(evaluation.get("approved") if evaluation else None)))

    lines = ["digraph agent_pipeline {", "  rankdir=LR;", "  node [shape=box, style=filled, fontname=\"Helvetica\"];"]

    for node_id, label, color in stages:
        lines.append(f'  {node_id} [label="{label}", fillcolor="{color}", fontcolor="white"];')

    for (left, _, _), (right, _, _) in zip(stages, stages[1:]):
        lines.append(f"  {left} -> {right};")

    if task_id:
        lines.append(f'  label="Задача: {task_id}";')

    lines.append("}")
    return "\n".join(lines)


def build_ast_dot(code: str, max_depth: int = 6, max_nodes: int = 80) -> str:
    """Строит dot-дерево абстрактного синтаксического дерева кода."""
    import ast as _ast

    try:
        tree = _ast.parse(code)
    except SyntaxError as exc:
        return f"digraph ast {{ node [shape=box]; \"синтаксическая ошибка: {exc.msg}\"; }}"

    lines = ["digraph ast {", "  node [shape=ellipse, fontname=\"Helvetica\"];"]
    counter = 0

    def _label(node: _ast.AST) -> str:
        name = type(node).__name__

        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef)):
            return f"{name}\\n{node.name}"
        if isinstance(node, _ast.Name):
            return f"Name\\n{node.id}"
        if isinstance(node, _ast.Constant):
            return f"Const\\n{repr(node.value)[:24]}"
        if isinstance(node, _ast.Attribute):
            return f"Attr\\n{node.attr}"
        if isinstance(node, _ast.Import):
            aliases = ",".join(alias.name for alias in node.names)[:24]
            return f"Import\\n{aliases}"
        return name

    def _walk(node: _ast.AST, parent_id: Optional[str], depth: int) -> None:
        nonlocal counter

        if depth > max_depth or counter >= max_nodes:
            return

        counter += 1
        node_id = f"n{counter}"
        lines.append(f'  {node_id} [label="{_label(node)}"];')

        if parent_id is not None:
            lines.append(f"  {parent_id} -> {node_id};")

        for child in _ast.iter_child_nodes(node):
            _walk(child, node_id, depth + 1)

    _walk(tree, None, 0)

    if counter >= max_nodes:
        lines.append("  truncated [label=\"... (обрезано)\", shape=plaintext];")

    lines.append("}")
    return "\n".join(lines)


def get_failure_analysis(df: pd.DataFrame) -> pd.DataFrame:
    """Анализирует причины отказов на основе логов."""
    if df.empty:
        return pd.DataFrame()

    failures = []

    for _, row in df.iterrows():
        event_type = row.get("event_type")
        payload = row.get("payload", {})

        if event_type == "task_denied":
            failures.append({
                "task_id": payload.get("task_id", ""),
                "stage": payload.get("stage", "unknown"),
                "reason": payload.get("reason", ""),
                "category": "denied",
            })

        elif event_type == "safety_check" and not payload.get("approved", True):
            failures.append({
                "task_id": payload.get("task_id", ""),
                "stage": "safety",
                "reason": ", ".join(payload.get("violations", [])),
                "category": "safety_violation",
            })

        elif event_type == "sandbox_execution" and not payload.get("success", True):
            failures.append({
                "task_id": payload.get("task_id", ""),
                "stage": "sandbox",
                "reason": payload.get("error", "unknown"),
                "category": "sandbox_failure",
            })

        elif event_type == "evaluation_result" and not payload.get("approved", True):
            failures.append({
                "task_id": payload.get("task_id", ""),
                "stage": "evaluation",
                "reason": payload.get("details", {}).get("reason", "evaluation_failed"),
                "category": "evaluation_failed",
            })

    return pd.DataFrame(failures)


def get_trust_level_history(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()

    trust_events = df[
        df["event_type"].isin(
            [
                "trust_updated_after_success",
                "trust_updated_after_failure",
                "trust_decision",
            ]
        )
    ].copy()

    if trust_events.empty:
        return pd.DataFrame()

    records: list[dict[str, Any]] = []

    for _, row in trust_events.iterrows():
        payload = row.get("payload", {})
        level = payload.get("level")

        if level:
            records.append(
                {
                    "datetime": row.get("datetime"),
                    "level": level,
                    "event_type": row.get("event_type"),
                }
            )

    return pd.DataFrame(records)
