# Инвентарь мёртвого кода: что спит, что живо (P4, 2026-09-14)

**Статус: report-only. Ничего не удалено и не будет без отдельного
решения оператора** — этот документ делает «40 модулей, из которых 30
спят» читаемой таблицей: для Phase-2 refactoring-плана и для разговоров
с инвесторами («5 честных модулей» вместо «40, в которых утонем»).

Метод: трассировка реальных импортов (кто импортирует модуль из живого
контура: API-вход `sentinel/api.py`, CLI-вход `audit_cli.py` →
`sia/flow_runner.py`, верификатор, SDK), упоминания в README/docs,
покрытие тестами. «Живой контур» = путь, который проходит аудит от
входа до квитанции (обе записи леджера реально прошли его).

## Живое ядро (не трогать — это продукт)

| Модуль | Почему живой |
|---|---|
| `sia/statistics.py`, `sia/llm_flow.py`, `sia/flow_runner.py`, `sia/audit.py`, `sia/cost_model.py`, `sia/models.py` | Обе записи леджера прошли этот путь |
| `sia/evaluation_engine.py`, `sia/optimizer.py`, `sia/model_catalog.py`, `sia/config.py` | Скрининг автопилота + code-flow + цены каталогов |
| `sentinel/` (api, auth, tenancy, billing, receipt_registry, merkle, cryptographic_receipts, anchoring, ed25519ph, audit_jobs, evidence_store, outbound_webhooks, database, atomic_write, cors) | Продуктовый сервер; `/v1/*` в README |
| `verifier/sia_verifier/*` | Независимый верификатор — суть стандарта |
| `sdk/sia_sentinel/client.py` | Публичный SDK из README |
| `scripts/`: anchor, beacon-датасет, gate_check, ledger_health, cron_ledger, drain, release, backup_zip, mirror, export_portal, postgres_smoke, demo_full, demo_forgery, falsification_battery | Операторский контур; каждый — в CI или чеклисте |
| `audit_cli.py`, `dashboard/` | Публичные входы из README |

## Дремлющие модули: таблица решений

Проверено трассировкой импортов 2026-09-14. «Вход» = единственный
способ дёрнуть модуль; если вход живой — модуль спит только до первого
использования, если вход сам спит — модуль мёртв целиком.

| Модуль | Вход в живой контур | Вердикт | Обоснование |
|---|---|---|---|
| `sia/multi_agent/` (5 файлов) | только `sia/cli.py` (не README-вход; см. ниже) | **МОРОЗИТЬ** | До-маячная многоагентная архитектура; ни одна запись не прошла через неё; `api.py` — 0 упоминаний |
| `sia/cli.py` | ничто из живого не импортирует (README ведёт в `audit_cli.py`) | **МОРОЗИТЬ** (вход сам спит) | Устаревший CLI: содержит code_agent/multi_agent/benchmark-обвязку; README-путь — `audit_cli.py` |
| `sia/code_agent.py` | `sia/cli.py` (спит) + `benchmark_runner` (спит) | **МОРОЗИТЬ** | Генерация кода агентом — не продуктовый путь (code-flow исполняет код клиента, а не генерирует) |
| `sia/benchmark_runner.py`, `sia/research_benchmark.py` | `sia/cli.py` (спит) | **МОРОЗИТЬ** | Наследие research-этапа; не в README, не в API, не в флоу |
| `sia/js_sandbox.py`, `sia/js_evaluation.py`, `sia/js_constitutional.py` | `benchmark_runner` (спит) | **МОРОЗИТЬ** | JS-оценка — не продуктовая метрика (была до-маячной) |
| `sia/constitutional_ai_layer.py` | `sentinel/api.py:20` — **ЖИВОЙ импорт**: `guard.check()` в `POST /v1/verify` | **ОСТАВИТЬ** | Не дремлющий (первоначальная классификация «строка-описание» — ошибка скана, поймана вороньей проверкой перед коммитом): safety-проверка предлагаемого кода — часть `/v1/verify` |
| `sia/sandbox_executor.py` | `sia/cli.py` + docker-зависимость | **МОРОЗИТЬ** | Docker-сэндбокс для code-flow CLI; сервер его не использует (validate_api_flow запрещает kind=code через API) |
| `sia/trust_level_manager.py` | `sentinel/api.py:28` — **ЖИВОЙ импорт** | **ОСТАВИТЬ** | Endpoint `/v1/agents/{id}/trust` — в публичном API |
| `sia/security_metrics.py`, `sia/tracing.py`, `sia/event_logger.py` | `trust_level_manager`/`orchestrator` (спящие) | **МОРОЗИТЬ** | Обвязка до-маячного агентного контура; ВНИМАНИЕ: `constitutional_ai_layer` (ОСТАВИТЬ, см. выше) импортирует часть этой обвязки — проверять импорт-граф при вырезке |
| `sia/orchestrator.py` | `sia/cli.py` (спит) | **МОРОЗИТЬ** | Наследие мультиагентного оркестратора |
| `sia/dashboard_data.py` | `dashboard/app.py` (README-вход) | **ОСТАВИТЬ** | Dashboard — публичная витрина из README |
| `sentinel/policy_engine.py`, `sentinel/webhook_handler.py`, `sentinel/github_client.py` | `sentinel/api.py` — **ЖИВЫЕ импорты** | **ОСТАВИТЬ** | `/v1/policies`, webhooks, GitHub-интеграция — в API |
| `scripts/oneoff/*` (5 файлов) | ничего; исторические фиксы 2026-08 | **ВЫРЕЗАТЬ при следующем major** | Одноразовые миграционные скрипты, своё отжили; уже исключены из ruff |

## Что это значит для кодовой базы

- **Живое ядро — 4 контура**: движок аудита, сервер, верификатор,
  операторские скрипты. Всё дремлющее — ветка «до-маячного» наследия,
  связанная одним входом (`sia/cli.py`), который сам не является входом
  проекта.
- **Морозка = ноль действий**: код остаётся в git (история не врёт),
  исключён из ментальной модели «что такое проект». Вырезка — отдельное
  решение оператора в Phase-2 (плюс: минус ~3-4k строк из ревью-обзора
  инвестора; минус: работа с import-графом и тестами).
- **Числа для разговора**: дремлющее — 14 модулей ≈ 3.5k строк; ядро
  (то, что реально произвело обе записи) — ~11k строк. Соотношение
  честно говорить как «ядро 3/4, наследие 1/4 — наследие заморожено и
  каталогизировано», а не «покрытие 77%» без контекста.

## Правило на будущее (для refactoring-plan Phase-2)

Новый модуль, не подключённый к живому контуру за 30 дней, попадает в
эту же таблицу автоматически (галочка при следующем инвентаре).
