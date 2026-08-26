"""Запуск аудита Proof-of-Savings по декларации флоу.

Единая точка входа для CLI (audit_cli.py) и API (sentinel): принимает
флоу-словарь (та же схема, что в JSON-файле для audit_cli) и возвращает
готовый отчёт. Здесь же живут защитные лимиты, чтобы внешний ввод не
устроил DoS аудитора.

Границы доверия:
- API (validate_api_flow): только inline-данные, никакого чтения файлов
  (*_file запрещены) и никакого kind="code" — исполнение клиентского кода
  в процессе API недопустимо (RCE → кража ключа подписи квитанций).
- CLI: *_file разрешены, но резолвятся строго внутри base_dir.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Optional, overload

from .audit import ProofOfSavingsAuditor
from .config import resolve_env
from .cost_model import PricingConfig
from .evaluation_engine import EvaluationEngine
from .llm_flow import DEFAULT_REPLAY_TOLERANCE, LLMEndpointConfig, LLMFlowAuditor
from .model_catalog import ModelCatalog, ModelSpec
from .optimizer import OptimizationGoal, SavingsOptimizer

# Защитные лимиты внешнего ввода.
# MAX_DATASET_ITEMS обязан оставаться НЕ статистическим ограничением:
# MDD = 2.80·√(p_disc/n) (односторонний alpha=2.5% + мощность 80%),
# поэтому δ=5 п.п. при 10% дискордантности требует n≈314, расхождение
# моделей ~20% — ~630 (чем сильнее расходятся модели, тем больше пар
# нужно). При старом лимите 200 публикуемый MDD (6.26 п.п.) превышал
# δ=5 п.п. — протокол не мог обосновать круглое пятипроцентное заявление
# на максимально разрешённом датасете.
MAX_DATASET_ITEMS = 1000
MAX_TEST_SUITE_ITEMS = 200
MAX_CODE_CHARS = 200_000
MAX_REPETITIONS = 10
MAX_CANDIDATES = 20

# Ключи флоу, ссылающиеся на файлы: разрешены только в CLI
FILE_KEYS = ("old_code_file", "new_code_file", "test_suite_file", "catalog_file")


def validate_api_flow(flow: dict[str, Any]) -> None:
    """Ограничения для флоу, пришедшего через HTTP API.

    - kind="code" исполняет клиентский код (exec) — в процессе API это RCE,
      поэтому через API запрещён; остаётся в CLI (локальный доверенный ввод).
    - *_file читают файлы сервера (абсолютный путь или ../ обходят базу) —
      через API только inline-данные.

    Бросает ValueError с объяснением.
    """
    if flow.get("kind", "code") == "code":
        raise ValueError(
            "kind='code' is not available via the API: executing untrusted "
            "code in the auditor process is disabled. Use the CLI "
            "(audit_cli.py) for code audits."
        )

    present = [key for key in FILE_KEYS if flow.get(key)]

    if present:
        raise ValueError(
            f"File references are not allowed via the API: {present}. "
            "Provide inline data instead (old_code/new_code/test_suite/candidates)."
        )


def _safe_join(base_dir: str, relative: str) -> str:
    """Разрешает путь внутри base_dir, не давая выйти наружу.

    os.path.join(".", "/etc/passwd") вернул бы "/etc/passwd" (абсолютный
    второй аргумент затирает базу), а "../../" вылез бы выше. Поэтому
    приводим к абсолютному и проверяем вложенность.
    """
    base = Path(base_dir).resolve()
    candidate = (base / relative).resolve()

    if not candidate.is_relative_to(base):
        raise ValueError(f"Path escapes base directory: {relative!r}")

    return str(candidate)


def run_flow_audit(
    flow: dict[str, Any],
    checkpoint_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Запускает аудит по флоу-декларации и возвращает отчёт (dict).

    checkpoint_dir: каталог JSONL-журналов возобновления для живых
    llm_flow-прогонов (см. sia.llm_flow._CheckpointJournal). None — без
    чекпойнта; API этот параметр не выставляет, это host-side забота.
    """
    kind = flow.get("kind", "code")

    if kind == "llm_flow":
        return _audit_llm_flow(flow, checkpoint_dir=checkpoint_dir)

    if kind == "code":
        return _audit_code_flow(flow)

    if kind == "optimize":
        return run_flow_optimization(flow)

    raise ValueError(f"Unknown flow kind: {kind}")


@overload
def _resolve_text(flow: dict[str, Any], inline_key: str, file_key: str, required: Literal[True]) -> str: ...


@overload
def _resolve_text(flow: dict[str, Any], inline_key: str, file_key: str, required: Literal[False]) -> str | None: ...


def _resolve_text(flow: dict[str, Any], inline_key: str, file_key: str, required: bool = True) -> str | None:
    if flow.get(inline_key):
        return flow[inline_key]

    if flow.get(file_key):
        file_path = _safe_join(flow.get("_base_dir", "."), flow[file_key])
        with open(file_path, "r", encoding="utf-8-sig") as handle:
            return handle.read()

    if required:
        raise ValueError(f"Flow must contain '{inline_key}' or '{file_key}'")

    return None


def _resolve_test_suite(flow: dict[str, Any]) -> list[str]:
    if flow.get("test_suite"):
        suite = list(flow["test_suite"])
    elif flow.get("test_suite_file"):
        import json

        file_path = _safe_join(flow.get("_base_dir", "."), flow["test_suite_file"])
        with open(file_path, "r", encoding="utf-8-sig") as handle:
            suite = json.load(handle)
    else:
        suite = []

    if len(suite) > MAX_TEST_SUITE_ITEMS:
        raise ValueError(f"test_suite too large (max {MAX_TEST_SUITE_ITEMS} items)")

    return suite


def _audit_code_flow(flow: dict[str, Any]) -> dict[str, Any]:
    old_code = _resolve_text(flow, "old_code", "old_code_file", True)
    new_code = _resolve_text(flow, "new_code", "new_code_file", True)

    if len(old_code) > MAX_CODE_CHARS or len(new_code) > MAX_CODE_CHARS:
        raise ValueError(f"code too large (max {MAX_CODE_CHARS} chars)")

    function_name = flow.get("function_name")

    if not function_name:
        raise ValueError("code flow requires 'function_name'")

    test_suite = _resolve_test_suite(flow)
    pricing_dict = flow.get("pricing") or {}

    # Тарификация включена по умолчанию; выключается явным "enable_costing": false
    pricing = None

    if flow.get("enable_costing", True):
        pricing = PricingConfig(
            compute_usd_per_hour=pricing_dict.get("compute_usd_per_hour", 2.0),
            input_token_usd_per_m=pricing_dict.get("input_token_usd_per_m", 0.15),
            output_token_usd_per_m=pricing_dict.get("output_token_usd_per_m", 0.60),
        )

    repetitions = min(int(flow.get("repetitions", 1)), MAX_REPETITIONS)

    delta = float(flow.get("delta", 0.0))
    if not 0.0 <= delta <= 1.0:
        raise ValueError("delta must be within [0, 1]")

    auditor = ProofOfSavingsAuditor(
        evaluation=EvaluationEngine(
            performance_iterations=flow.get("performance_iterations", 100),
            performance_repeat=flow.get("performance_repeat", 2),
            benchmark_timeout=flow.get("benchmark_timeout", 60.0),
        )
    )

    report = auditor.audit(
        old_code=old_code,
        new_code=new_code,
        function_name=function_name,
        test_suite=test_suite,
        args_template=tuple(flow.get("args_template", ())),
        pricing=pricing,
        confidence=flow.get("confidence", 0.95),
        repetitions=repetitions,
        seeds=tuple(flow.get("seeds", (42,))),
        delta=delta,
    )

    report_dict = report.to_dict()
    report_dict["name"] = flow.get("name", "unnamed-code-flow")
    report_dict["kind"] = "code"
    return report_dict



def _replay_tolerance_from_flow(flow: dict[str, Any]) -> float:
    """Допуск реплея из флоу; без ключа — измеренный дефолт 0.05."""
    value = flow.get("replay_tolerance", DEFAULT_REPLAY_TOLERANCE)

    try:
        tolerance = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"replay_tolerance must be a number in (0, 1), got {value!r}"
        ) from exc

    if not 0.0 < tolerance < 1.0:
        raise ValueError(
            f"replay_tolerance must be in (0, 1), got {tolerance}"
        )

    return tolerance


def build_preregistration_commitment(flow: dict[str, Any]) -> dict[str, Any]:
    """Строит обязательство предрегистрации из flow-декларации БЕЗ запуска аудита.

    Используется API для коммита параметров в цепочку ДО прогона.
    Поддерживает kind=llm_flow и kind=optimize (у optimize — датасет и
    базовая конфигурация). Для kind=code предрегистрация не применяется
    (code-аудиты идут только через CLI с доверенным локальным вводом).

    ПРАВИЛО «НЕТ ЯКОРЯ — НЕТ ЗАПИСИ» В КОДЕ, НЕ В ПАМЯТИ: флоу обязан нести
    явное anchor_declaration ('external-anchor' или 'unanchored') — без него
    регистрация отказывает. Молчаливое прохождение оператором, который не
    знает о договорённостях этого разговора, исключено; признание
    замораживается в леджере рядом с остальными параметрами.
    """
    kind = flow.get("kind")

    if kind not in ("llm_flow", "optimize"):
        raise ValueError(f"preregistration is not supported for kind={kind!r}")

    anchor_declaration = (flow.get("anchor_declaration") or "").strip()

    if not anchor_declaration:
        raise ValueError(
            "flow must carry an explicit 'anchor_declaration' before "
            "preregistration ('external-anchor' or 'unanchored'). Anchoring "
            "is not optional by default; a silent pass would let record №7 "
            "ship unanchored because an operator never heard the rule."
        )

    # external-anchor — положительное заявление, оно обязано быть
    # проверяемым. Формы несут РАЗНУЮ силу (зафиксировано в спеке):
    #   rekor:<entry-id>:<index> — указатель в ПУБЛИЧНЫЙ append-only лог,
    #     третья сторона достаёт запись сама; entry-id у публичного
    #     инстанса 64 ИЛИ 80 hex (шардированный ID = дерево+лист) —
    #     строгая проверка «ровно 64» отвергла бы настоящий ответ ровно
    #     в момент записи №1;
    #   rfc3161:<64hex> — дайджест CMS-токена: сам по себе нигде не
    #     достаётся, он связывает токен, который оператор обязан
    #     опубликовать рядом; до публикации проверить нельзя.
    # Голые значения без префикса отвергаются: форма обязана быть
    # самоописывающей.
    anchor_reference = (flow.get("anchor_reference") or "").strip()

    if anchor_declaration == "external-anchor":
        import re as _re

        if not _re.fullmatch(
            r"rekor:(?:[0-9a-f]{64}|[0-9a-f]{80}):\d+|rfc3161:[0-9a-f]{64}",
            anchor_reference or "",
        ):
            raise ValueError(
                "anchor_declaration='external-anchor' requires a verifiable "
                "'anchor_reference': 'rekor:<entry-id>:<log-index>' (entry "
                "id is 64 or 80 hex as the public instance returns) or "
                "'rfc3161:<64-hex token digest>'. A bare claim of anchoring "
                "is trust-shaped, not proof."
            )

    dataset = flow.get("dataset") or []
    if not dataset:
        raise ValueError("preregistration requires a non-empty 'dataset'")
    if len(dataset) > MAX_DATASET_ITEMS:
        raise ValueError(f"dataset too large (max {MAX_DATASET_ITEMS} items)")

    confidence = flow.get("confidence", 0.95)
    delta = float(flow.get("delta", 0.05))
    repetitions = min(int(flow.get("repetitions", 1)), MAX_REPETITIONS)

    if kind == "llm_flow":
        old_block = flow.get("old") or {}
        new_block = flow.get("new") or {}
        old_config = _endpoint_from_block(old_block)
        new_config = _endpoint_from_block(new_block)
    else:  # optimize
        baseline_block = flow.get("baseline") or {}
        old_config = _endpoint_from_block(baseline_block)
        new_config = old_config  # кандидаты выбираются оптимизатором

    return LLMFlowAuditor.preregistration_commitment(
        dataset=dataset,
        old_config=old_config,
        new_config=new_config,
        delta=delta,
        confidence=confidence,
        repetitions=repetitions,
        replay_tolerance=_replay_tolerance_from_flow(flow),
        anchor_declaration=anchor_declaration,
        anchor_reference=anchor_reference or None,
    )


def _audit_llm_flow(
    flow: dict[str, Any],
    checkpoint_dir: Optional[Path] = None,
) -> dict[str, Any]:
    dataset = flow.get("dataset") or []

    if not dataset:
        raise ValueError("llm_flow requires a non-empty 'dataset'")

    if len(dataset) > MAX_DATASET_ITEMS:
        raise ValueError(f"dataset too large (max {MAX_DATASET_ITEMS} items)")

    old_block = flow.get("old") or {}
    new_block = flow.get("new") or {}
    pricing_block = flow.get("pricing") or {}

    defaults = PricingConfig(
        input_token_usd_per_m=pricing_block.get("input_token_usd_per_m", 0.15),
        output_token_usd_per_m=pricing_block.get("output_token_usd_per_m", 0.60),
    )

    # Один сборщик эндпоинта и для аудита, и для предрегистрации: раньше
    # локальный дубликат _endpoint не передавал prices_as_of/catalog_version,
    # и манифест аудита терял датировку цен, которую несло обязательство
    # предрегистрации (E5 отваливался ровно на пути аудита).
    auditor = LLMFlowAuditor(defaults=defaults)

    old_config = _endpoint_from_block(old_block)
    new_config = _endpoint_from_block(new_block)
    repetitions = min(int(flow.get("repetitions", 1)), MAX_REPETITIONS)
    confidence = flow.get("confidence", 0.95)
    delta = float(flow.get("delta", 0.05))

    report = auditor.audit_flow(
        dataset=dataset,
        old_config=old_config,
        new_config=new_config,
        repetitions=repetitions,
        confidence=confidence,
        delta=delta,
        checkpoint_dir=checkpoint_dir,
    )

    report_dict = report.to_dict()
    report_dict["name"] = flow.get("name", "unnamed-llm-flow")
    report_dict["kind"] = "llm_flow"
    # Ворота живости/цен, прогнанные В ТОМ ЖЕ сеансе перед прогоном
    # (scripts/gate_check.py печатает готовый словарь): попадают в
    # манифест -> под подпись code_hash. Манифест не входит в коммитмент,
    # поэтому формат обязательства не меняется; время ворот публикуется,
    # а не остаётся в болтовне сессии.
    gate_evidence = flow.get("gate_evidence")

    if gate_evidence:
        report_dict["manifest"]["gate_evidence"] = gate_evidence
    # Обязательство предрегистрации: хеши параметров аудита, которые
    # должны быть закоммичены в цепочку ДО прогона (см. sentinel API).
    report_dict["preregistration"] = LLMFlowAuditor.preregistration_commitment(
        dataset=dataset,
        old_config=old_config,
        new_config=new_config,
        delta=delta,
        confidence=confidence,
        repetitions=repetitions,
        replay_tolerance=_replay_tolerance_from_flow(flow),
    )
    return report_dict


def _endpoint_from_block(block: dict[str, Any]) -> LLMEndpointConfig:
    """Общая сборка эндпоинта из блока флоу (api_key_env через resolve_env)."""
    api_key = block.get("api_key")

    if not api_key and block.get("api_key_env"):
        api_key = resolve_env(block["api_key_env"])

    return LLMEndpointConfig(
        model_name=block.get("model_name", "unknown-model"),
        input_token_usd_per_m=block.get("input_token_usd_per_m"),
        output_token_usd_per_m=block.get("output_token_usd_per_m"),
        base_url=block.get("base_url"),
        api_key=api_key,
        temperature=block.get("temperature", 0.0),
        reasoning_effort=block.get("reasoning_effort"),
        profile=block.get("profile", "standard"),
        seed=block.get("seed", 42),
        prices_as_of=block.get("prices_as_of"),
        catalog_version=block.get("catalog_version"),
        price_source_url=block.get("price_source_url"),
        priced_model_name=block.get("priced_model_name"),
        price_basis_note=block.get("price_basis_note"),
    )


def run_flow_optimization(flow: dict[str, Any]) -> dict[str, Any]:
    """Оптимизация: подбор самой дешёвой конфигурации, сохраняющей качество.

    Схема флоу:
        {"kind": "optimize", "name": "...",
         "dataset": [{"prompt": "...", "expect_contains": "..."}],
         "baseline": {"model_name": "...", ...},          # текущая конфигурация
         "candidates": [{"model_name": "...", ...}],      # или catalog_file
         "quality_floor": 0.9, "confidence": 0.95,
         "screening_fraction": 0.5, "final_repetitions": 2, "max_finalists": 3}
    """
    dataset = flow.get("dataset") or []

    if not dataset:
        raise ValueError("optimize flow requires a non-empty 'dataset'")

    if len(dataset) > MAX_DATASET_ITEMS:
        raise ValueError(f"dataset too large (max {MAX_DATASET_ITEMS} items)")

    baseline_block = flow.get("baseline")

    if not baseline_block:
        raise ValueError("optimize flow requires 'baseline'")

    candidates = _resolve_candidates(flow)

    goal = OptimizationGoal(
        dataset=tuple(dataset),
        quality_floor=float(flow.get("quality_floor", 0.90)),
        confidence=float(flow.get("confidence", 0.95)),
        screening_fraction=float(flow.get("screening_fraction", 0.5)),
        final_repetitions=min(int(flow.get("final_repetitions", 2)), MAX_REPETITIONS),
        max_finalists=int(flow.get("max_finalists", 3)),
    )

    optimizer = SavingsOptimizer()

    result = optimizer.optimize(
        goal=goal,
        baseline=_endpoint_from_block(baseline_block),
        candidates=candidates,
    )

    result_dict = result.to_dict()
    result_dict["name"] = flow.get("name", "unnamed-optimization")
    result_dict["kind"] = "optimize"
    return result_dict


def _resolve_candidates(flow: dict[str, Any]) -> list[ModelSpec]:
    """Кандидаты из inline-списка или файла каталога (с опциональным фильтром)."""
    if flow.get("candidates"):
        candidates = [ModelSpec.from_dict(item) for item in flow["candidates"]]
    elif flow.get("catalog_file"):
        catalog_path = _safe_join(flow.get("_base_dir", "."), flow["catalog_file"])
        catalog = ModelCatalog.from_json(catalog_path)
        candidates = catalog.filter(
            tags=flow.get("tags"),
            tiers=flow.get("tiers"),
            exclude=flow.get("exclude"),
        )
    else:
        raise ValueError("optimize flow requires 'candidates' or 'catalog_file'")

    if not candidates:
        raise ValueError("optimize flow resolved to an empty candidate list")

    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"too many candidates (max {MAX_CANDIDATES})")

    return candidates
