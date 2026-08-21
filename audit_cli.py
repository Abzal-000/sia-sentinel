#!/usr/bin/env python3
"""Batch-аудит Proof-of-Savings: одна команда — проверяемое доказательство экономии.

Поддерживает два вида флоу (JSON-файл со схемой ниже):

kind=code — пара версий кода:
    {"kind": "code", "name": "...", "function_name": "fib",
     "old_code": "...", "new_code": "...",            # или *_file
     "test_suite": ["assert ..."],                     # или test_suite_file
     "args_template": [20],
     "pricing": {"compute_usd_per_hour": 3.6},
     "repetitions": 2, "seeds": [42]}

kind=llm_flow — пара LLM-эндпоинтов (mode=simulated без ключей / live):
    {"kind": "llm_flow", "name": "...",
     "dataset": [{"prompt": "...", "expect_contains": "..."}],
     "old": {"model_name": "premium", "profile": "verbose",
             "input_token_usd_per_m": 3.0, "output_token_usd_per_m": 15.0},
     "new": {"model_name": "small", "profile": "concise"},
     "repetitions": 3}

kind=optimize — Savings Autopilot: подбор самой дешёвой конфигурации,
сохраняющей качество (каталог кандидатов + базовая конфигурация):
    {"kind": "optimize", "name": "...",
     "dataset": [{"prompt": "...", "expect_contains": "..."}],
     "baseline": {"model_name": "meta/llama-3.3-70b-instruct", ...},
     "catalog_file": "model_catalog.json",   # или "candidates": [...]
     "quality_floor": 0.9, "max_finalists": 3}

Выход: report.json (--out), человекочитаемый отчёт (--markdown),
подписанная квитанция Ed25519 с манифестом (--sign).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

sys.path.insert(0, str(Path(__file__).parent))

from sia.flow_runner import run_flow_audit


def _load_flow(path: str) -> dict[str, Any]:
    flow_path = Path(path)

    if not flow_path.is_file():
        raise SystemExit(f"Flow file not found: {path}")

    with open(flow_path, "r", encoding="utf-8-sig") as handle:
        flow = json.load(handle)

    kind = flow.get("kind", "code")
    if kind not in ("code", "llm_flow", "optimize"):
        raise SystemExit(f"Unknown flow kind: {kind}")

    return flow


def audit_code_flow(flow: dict[str, Any]) -> dict[str, Any]:
    """Совместимость: аудит code-флоу через общий движок."""
    flow = {**flow, "kind": "code"}
    return run_flow_audit(flow)


def audit_llm_flow(flow: dict[str, Any]) -> dict[str, Any]:
    """Совместимость: аудит llm_flow через общий движок."""
    flow = {**flow, "kind": "llm_flow"}
    return run_flow_audit(flow)


def to_markdown(report: dict[str, Any]) -> str:
    if report.get("kind") == "optimize":
        return _optimization_to_markdown(report)

    claim = report.get("claim", {})
    name = report.get("name", "unnamed")
    kind = report.get("kind", "code")
    lines = [
        "# Proof-of-Savings Report",
        "",
        f"- **Flow:** {name} (`{kind}`)",
        f"- **Protocol:** {report.get('protocol', 'proof-of-savings/1')}",
    ]

    if report.get("mode"):
        lines.append(f"- **Mode:** {report['mode']}")

    lines.extend([
        "",
        "## Claim",
        "",
        f"- Savings verified: **{claim.get('savings_verified')}**",
    ])

    if "savings_ratio" in claim:
        lines.append(f"- Savings ratio: **{claim['savings_ratio']:.1%}**")

    if "old_unit_cost_usd" in claim:
        lines.append(
            f"- Unit cost: ${claim['old_unit_cost_usd']:.6f} → "
            f"${claim['new_unit_cost_usd']:.6f}"
        )

    if claim.get("savings_usd_per_1k_runs") is not None:
        lines.append(f"- Projected savings: **${claim['savings_usd_per_1k_runs']} per 1,000 runs**")
    elif claim.get("savings_usd_per_1k_calls") is not None:
        lines.append(f"- Projected savings: **${claim['savings_usd_per_1k_calls']} per 1,000 calls**")

    ci = claim.get("equivalence_ci")
    if ci:
        lines.append(
            f"- Quality preserved: {report['equivalence'].get('verdict')} "
            f"(95% CI [{ci[0]:.3f}, {ci[1]:.3f}], "
            f"{report['equivalence'].get('repetitions')} reps)"
        )

    if "performance" in report:
        perf = report["performance"]
        if perf.get("gain") is not None:
            lines.append(f"- Speedup: {perf['gain']:.1%}")

    if "usage_old" in report:
        lines.extend([
            "",
            "## Token usage",
            "",
            "| Endpoint | Calls | In tokens | Out tokens | Avg latency | Unit cost |",
            "|---|---|---|---|---|---|",
        ])

        for label, usage_key in (("old", "usage_old"), ("new", "usage_new")):
            usage = report[usage_key]
            lines.append(
                f"| {label} | {usage['calls']} | {usage['input_tokens']} | "
                f"{usage['output_tokens']} | {usage['avg_latency_sec']*1000:.1f} ms | "
                f"${usage['unit_cost_usd']:.6f} |"
            )

    manifest = report.get("manifest", {})
    lines.extend([
        "",
        "## Reproducibility manifest",
        "",
        "```json",
        json.dumps(manifest, indent=2, sort_keys=True, default=str),
        "```",
        "",
        "_Generated by SIA Proof-of-Savings auditor._",
    ])

    return "\n".join(lines)


def _optimization_to_markdown(report: dict[str, Any]) -> str:
    """Человекочитаемый отчёт Savings Autopilot."""
    rec = report.get("recommendation")
    goal = report.get("goal", {})
    baseline = report.get("baseline", {})
    lines = [
        "# Savings Autopilot Report",
        "",
        f"- **Flow:** {report.get('name', 'unnamed')} (`optimize`)",
        f"- **Protocol:** {report.get('protocol', 'proof-of-savings-optimization/1')}",
        f"- **Dataset:** {goal.get('dataset_size')} cases, "
        f"quality floor {goal.get('quality_floor')}, "
        f"confidence {goal.get('confidence')}",
        f"- **Baseline:** {baseline.get('model_name')} "
        f"(${baseline.get('unit_cost_usd', 0):.6f}/call)",
        "",
    ]

    if rec:
        lines.extend([
            "## Recommendation",
            "",
            f"- **Best model:** `{rec.get('model_name')}`",
            f"- Savings verified: **{rec.get('savings_verified')}**",
            f"- Savings ratio: **{rec.get('savings_ratio', 0):.1%}**",
            f"- Unit cost: ${rec.get('old_unit_cost_usd', 0):.6f} → "
            f"${rec.get('new_unit_cost_usd', 0):.6f}",
            f"- Projected savings: **${rec.get('savings_usd_per_1k_calls', 0)} "
            f"per 1,000 calls**",
            "",
        ])
    else:
        lines.extend([
            "## Recommendation",
            "",
            "_No candidate proved savings while preserving quality._",
            "",
        ])

    candidates = report.get("candidates", [])
    if candidates:
        lines.extend([
            "## Candidate screening",
            "",
            "| Model | Stage | Pass rate | CI lower | Unit cost | Eliminated |",
            "|---|---|---|---|---|---|",
        ])

        for ev in candidates:
            lines.append(
                f"| {ev['model_name']} | {ev['stage']} | "
                f"{ev['pass_rate']:.1%} | {ev['ci_lower']:.3f} | "
                f"${ev['unit_cost_usd']:.6f} | {ev['eliminated']} |"
            )

        lines.append("")

    manifest = report.get("manifest", {})
    lines.extend([
        "## Reproducibility manifest",
        "",
        "```json",
        json.dumps(manifest, indent=2, sort_keys=True, default=str),
        "```",
        "",
        "_Generated by SIA Savings Autopilot._",
    ])

    return "\n".join(lines)


def sign_report(report: dict[str, Any]) -> dict[str, Any]:
    """Подписывает отчёт квитанцией Ed25519 с манифестом (sentinel)."""
    from sentinel.cryptographic_receipts import ReceiptGenerator

    if report.get("kind") == "optimize":
        claim = report.get("recommendation") or {}
    else:
        claim = report.get("claim", {})

    generator = ReceiptGenerator()
    receipt = generator.generate_receipt(
        evidence_id=f"pos-{report.get('name', 'flow')}",
        code=json.dumps(report, sort_keys=True, default=str),
        safety_approved=bool(claim.get("savings_verified")),
        trust_level="JUNIOR",
        manifest=report.get("manifest"),
    )

    receipt_dict = receipt.to_dict()
    receipt_dict["verification"] = {
        "public_key": generator.get_public_key(),
        "algorithm": "Ed25519-SHA256",
        "note": "verify via ReceiptVerifier(public_key).verify_json(json.dumps(receipt))",
    }

    return receipt_dict


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit_cli",
        description="Proof-of-Savings batch auditor",
    )

    parser.add_argument("--flow", required=True, help="Path to flow JSON file")
    parser.add_argument("--out", default=None, help="Write JSON report to this file")
    parser.add_argument("--markdown", default=None, help="Write Markdown report to this file")
    parser.add_argument("--sign", default=None, help="Write signed Ed25519 receipt to this file")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    flow = _load_flow(args.flow)
    flow["_base_dir"] = str(Path(args.flow).resolve().parent)

    kind = flow.get("kind", "code")

    if kind == "llm_flow":
        report = audit_llm_flow(flow)
    elif kind == "optimize":
        report = run_flow_audit(flow)
    else:
        report = audit_code_flow(flow)

    report_json = json.dumps(report, indent=2, default=str)

    if args.out:
        Path(args.out).write_text(report_json, encoding="utf-8")
        print(f"JSON report:    {args.out}")
    else:
        print(report_json)

    if args.markdown:
        Path(args.markdown).write_text(to_markdown(report), encoding="utf-8")
        print(f"Markdown report: {args.markdown}")

    if args.sign:
        receipt = sign_report(report)
        Path(args.sign).write_text(
            json.dumps(receipt, indent=2, default=str), encoding="utf-8"
        )
        print(f"Signed receipt:  {args.sign}")
        print(f"Public key:      {receipt['verification']['public_key']}")

    if report.get("kind") == "optimize":
        claim = report.get("recommendation") or {}
    else:
        claim = report.get("claim", {})

    verified = claim.get("savings_verified")

    if "savings_ratio" in claim:
        print(f"Savings: {claim['savings_ratio']:.1%} | verified: {verified}")
    elif report.get("kind") == "optimize":
        print("Savings: no candidate verified | verified: False")

    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
