#!/usr/bin/env python3
"""Ворота живости и цен ПЕРЕД записью №1 — в одном сеансе с прогоном.

Печатает готовый словарь gate_evidence: по одному реальному вызову на
каждое плечо флоу (латентность, токены, отпечаток обслужившего бэкенда)
+ сверка цен флоу против публичного списка OpenRouter. Словарь вставляется
в ключ flow "gate_evidence" и уезжает в манифест отчёта под подпись —
время ворот публикуется внутри записи, а не остаётся в болтовне сессии.

    python scripts/gate_check.py --flow flows/beacon.json

$0; запускать НЕ заранее, непосредственно перед preregistration/прогоном.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from sia.flow_runner import _endpoint_from_block  # noqa: E402
from sia.llm_flow import OpenAICompatibleClient  # noqa: E402


def openrouter_price(model_id: str) -> dict:
    """Ставка ИМЕННО Groq из списка OpenRouter для тех же весов.

    Имена эндпоинтов имеют форму 'Провайдер | model'; ищем содержащее
    'groq' — смысл ворот в том, что платящий пользователь попадает к тому
    же сервингу, который обслуживает нас бесплатно.
    """
    url = f"https://openrouter.ai/api/v1/models/{model_id}/endpoints"
    req = urllib.request.Request(url, headers={"User-Agent": "sia-audit/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.load(r)["data"]

    for ep in data.get("endpoints", []):
        if "groq" in ep["name"].lower():
            p = ep["pricing"]
            return {
                "input": float(p["prompt"]) * 1_000_000,
                "output": float(p["completion"]) * 1_000_000,
                "provider": ep["name"],
            }
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flow", required=True)
    args = parser.parse_args()

    flow = json.loads(Path(args.flow).read_text(encoding="utf-8-sig"))
    checked_at = dt.datetime.now(dt.timezone.utc).isoformat()
    evidence: dict = {"checked_at": checked_at, "sides": {}}

    for side in ("old", "new"):
        block = flow[side]
        config = _endpoint_from_block(block)
        client = OpenAICompatibleClient(config, request_timeout=60, max_retries=2)
        started = time.perf_counter()
        result = client.complete(
            "What is 17*23? Reply with exactly one line: ANSWER=<integer>"
        )
        latency = round(time.perf_counter() - started, 2)
        listed = openrouter_price(config.model_name)
        price_ok = bool(listed) and abs(
            listed["input"] - block["input_token_usd_per_m"]
        ) < 1e-9 and abs(
            listed["output"] - block["output_token_usd_per_m"]
        ) < 1e-9
        evidence["sides"][side] = {
            "model_name": config.model_name,
            "alive": True,
            "latency_sec": latency,
            "out_tokens": result.output_tokens,
            "answer_tail": (result.text.strip().splitlines() or [""])[-1][:30],
            "served_model_name": result.served_model_name,
            "list_rate_matches_flow": price_ok,
            "list_rate": listed,
        }
        print(f"{side}: {config.model_name} {latency}s out={result.output_tokens} "
              f"price_match={price_ok}")

    evidence["prices_checked_at"] = checked_at
    print("\n\"gate_evidence\":")
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
