# Публикация sia-verifier на PyPI — ✅ ВЫПОЛНЕНО 2026-09-06

> **1.3.1 (2026-09-13): собрана, загрузка на PyPI НЕ сделана.** Изменение:
> `--checkpoint` понимает JSONL-журнал снимков (проверяются ВСЕ строки,
> не только последняя) — нужно после появления второго чекпойнта в
> `receipts/checkpoints.jsonl`; 1.3.0 с PyPI на двухстрочном журнале
> честно падает с ошибкой чтения. Артефакты: `verifier/dist/sia_verifier-1.3.1*`.
> Загрузка — тот же twine-протокол из раздела ниже (15 минут, нужен PyPI-токен).

**Статус: ОПУБЛИКОВАНО.** `pip install sia-verifier` работает для любого
человека; подтверждено установкой из чистого venv и верификацией записи №1
(`VERDICT: VALID`), метаданные живые: pypi.org/pypi/sia-verifier/json →
version 1.3.0, wheel + sdist на месте. Раздел ниже оставлен как протокол
проведённой процедуры; правила версий (в конце) — действующие.

Протокол (2026-09-06, фактический): аккаунт + 2FA → API-токен (в менеджер
паролей) → `twine upload dist/*` из PowerShell (формат «Enter your API
token», токен целиком) → проверка в чистом venv
(`pip install sia-verifier` → `sia-verifier attestation.json --chain
registry.jsonl --checkpoint checkpoints.jsonl` → VERDICT: VALID).

## Что уже сделано (не повторять)

- `verifier/pyproject.toml`: версия 1.3.0, четыре console-скрипта.
- `sia_verifier/__init__.py`: 1.3.0, описание CLI.
- Сборка: `cd verifier && python -m build` → `dist/sia_verifier-1.3.0*`.
- Изолированная проверка: venv без проекта → `pip install <wheel>` →
  все команды отработали на `artifacts/record1`.

## Шаги оператора (один раз, ~15 минут)

1. **Аккаунт PyPI** (если нет): https://pypi.org/account/register/
   — подтвердить email, включить 2FA (обязательно для аплоада).

2. **API-токен**: pypi.org → Account settings → API tokens →
   «Add API token», scope: «Entire account» (для первого пакета) или
   проект будет создан при первом аплоаде. Токен вида
   `pypi-AgEIcHlwaS5vcmc...` — В МЕНЕДЖЕР ПАРОЛЕЙ, не в чат и не в файлы
   репозитория.

3. **Проверка перед аплоадом** (опционально, но рекомендовано):
   сначала на TestPyPI (отдельный токен, отдельный аккаунт —
   https://test.pypi.org):
   ```bash
   cd verifier
   ../venv/Scripts/python.exe -m twine upload --repository testpypi dist/*
   # затем проверка установки ОТТУДА в чистый venv
   ```

4. **Аплоад на PyPI**:
   ```bash
   cd verifier
   ../venv/Scripts/python.exe -m twine upload dist/*
   # username: __token__, password: <API-токен целиком>
   ```

5. **Немедленная проверка** (чистый venv):
   ```bash
   python -m venv %TEMP%/sia_check && %TEMP%/sia_check/Scripts/pip install sia-verifier
   %TEMP%/sia_check/Scripts/sia-verifier artifacts/record1/attestation.json
   ```

6. **После успеха**: обновить эту страницу (пометить «опубликовано»),
   убрать оговорку «до публикации» из verify-in-5-minutes.md и
   record1-how-to-reverify.md, закоммитить.

## Правила версий

- 1.3.0 — текущая (replay Б2 + rederive + holdout); 1.2.0 — была первая
  это серверная часть).
- Любое изменение `core.py`/`rederive.py`/`holdout.py` → бамп версии
  (патч — багфикс, минор — новая проверка/команда) и пересборка.

## Если название занято

`pypi.org/project/sia-verifier` — проверить перед аплоадом. Если вдруг
занято (маловероятно): варианты `sia-attestation-verifier`, `sia-sentinel-verifier`;
тогда поменять `name` в pyproject.toml, пересобрать, обновить все
упоминания в README/docs.
