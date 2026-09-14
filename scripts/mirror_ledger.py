#!/usr/bin/env python3
"""WORM-зеркало леджера: append-only публикация истории доверия.

Ирония, закрытая этим скриптом: продукт, чья суть — тампер-эвидентная
история, «которую нельзя переписать», жил на одном диске. Теперь леджер
в git (вторая точка существования), но git-remote по умолчанию — НЕ
WORM: ``git push --force`` может переписать историю, и весь смысл
внешнего якоря теряется. Этот скрипт делает публикацию механически
append-only:

  1. Локальная цепь обязана быть VALID до головы (зеркалить битую
     историю — реплицировать повреждение).
  2. Зеркало обязано РАСШИРЯТЬ историю: голова зеркала (если есть) —
     строгий префикс локальной. Расхождение (локал короче, голове зеркала
     нет места в локальной цепи) — отказ: кто-то уже переписал локал
     ИЛИ зеркало, и это человек-алерт, а не «переконвергенция».
  3. Публикуются ТОЛЬКО trust-bearing файлы: registry.jsonl,
     checkpoints.jsonl, anchors/*.json. Скрипт отказывается пушить
     что-либо ещё (рабочий каталог с черновиками — не история доверия).

На стороне GitHub WORM ДОПОЛНИТЕЛЬНО защищается branch-protection
(rule «Restrict deletions» + блок force-push); скрипт проверяет, что
remote настроен, и напоминает включить защиту, если нет. Без защиты
на стороне хоста append-only — конвенция; с ней — правило хоста.

Выходные коды (cron-friendly):
  0 — зеркало актуально или расширено; 1 — гейт отказал (локальная
  проблема); 2 — расхождение с зеркалом (человек-алерт); 3 — ошибка
  среды (нет git/remote).

Запуск:
    python scripts/mirror_ledger.py --dry-run   # показать, что изменится
    python scripts/mirror_ledger.py              # закоммитить и запушить
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY = REPO_ROOT / "receipts" / "registry.jsonl"
CHECKPOINTS = REPO_ROOT / "receipts" / "checkpoints.jsonl"
ANCHORS = REPO_ROOT / "anchors"

# Windows-консоли (CP866/CP1251) молча роняют кириллический вывод в
# UnicodeEncodeError, который argparse/pytest проглатывают как тишину;
# print обязан доживать до глаз оператора в любой консоли
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Только эти пути — история доверия; всё остальное — не пушим
TRUST_PATHS = ("receipts/registry.jsonl", "receipts/checkpoints.jsonl", "anchors/")

sys.path.insert(0, str(REPO_ROOT / "verifier"))
from sia_verifier.core import verify_chain  # noqa: E402


def _git(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and proc.returncode != 0:
        print(proc.stderr.strip() or proc.stdout.strip(), file=sys.stderr)
        raise SystemExit(3)
    return proc


def _load_entries(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out


def local_chain_head() -> dict:
    entries = _load_entries(REGISTRY)
    verdict = verify_chain(entries)
    if not verdict.valid:
        print(
            f"GATE 1 FAILED: local chain is INVALID ({verdict.reason} at "
            f"{verdict.broken_at}) — refusing to replicate damaged history",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return {"seq": entries[-1]["seq"], "hash": entries[-1]["entry_hash"], "count": len(entries)}


def mirror_head() -> dict | None:
    """Голова леджера на remote (по origin/master) или None, если зеркала нет."""
    _git(["fetch", "--quiet", "origin"])
    proc = _git(["show", "origin/master:receipts/registry.jsonl"], check=False)
    if proc.returncode != 0:
        return None
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        return None
    entries = [json.loads(ln) for ln in lines]
    return {"seq": entries[-1]["seq"], "hash": entries[-1]["entry_hash"], "count": len(entries)}


def gate_2_mirror_extends(local: dict, mirror: dict | None) -> None:
    """Зеркало обязано быть строгим префиксом локальной истории.

    Локал короче зеркала или голова зеркала не совпадает ни с одной
    локальной записью — кто-то переписал одну из сторон. Это не
    «конфликт слияния», это событие безопасности.
    """
    if mirror is None:
        return  # первое зеркало — расширение по определению

    if local["count"] < mirror["count"]:
        print(
            f"GATE 2 FAILED: mirror has {mirror['count']} entries but local has "
            f"{local['count']} — local history was rewritten or truncated. "
            "HUMAN ALERT: do not force-push; recover the mirror first.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    mirror_entry = _mirror_entry_by_seq(mirror["seq"])
    if mirror_entry is None or mirror_entry.get("entry_hash") != mirror["hash"]:
        print(
            f"GATE 2 FAILED: mirror head (seq={mirror['seq']}) is not in the local "
            "chain — histories diverged. HUMAN ALERT: investigate before pushing.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    print(f"gate 2: mirror is a prefix of local history (mirror seq={mirror['seq']}, local seq={local['seq']})")


def _mirror_entry_by_seq(seq: int) -> dict | None:
    for entry in _load_entries(REGISTRY):
        if entry.get("seq") == seq:
            return entry
    return None


def gate_3_only_trust_paths_staged() -> None:
    staged = _git(["diff", "--cached", "--name-only"]).stdout.splitlines()
    unexpected = [p for p in staged if p and not any(p == t or p.startswith(t) for t in TRUST_PATHS)]
    if unexpected:
        print(
            "GATE 3 FAILED: non-trust files staged for the mirror push: "
            f"{unexpected}. The mirror publishes ledger history only.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if staged:
        print(f"gate 3: staged paths are trust-bearing ({len(staged)} file(s))")


def branch_protection_reminder() -> None:
    """Напоминание, если на remote нет ветки зеркала/защиты — проверить API нельзя без токена хоста, поэтому просто напоминаем один раз в коммите."""
    print(
        "reminder: ensure the remote branch has force-push/deletion disabled "
        "(GitHub: Settings → Branches → branch protection). Append-only on "
        "the host side is what makes the mirror WORM."
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Append-only ledger mirror")
    parser.add_argument("--dry-run", action="store_true", help="show what would be pushed")
    args = parser.parse_args()

    remote = _git(["remote", "get-url", "origin"], check=False)
    if remote.returncode != 0 or not remote.stdout.strip():
        print("GATE 0 FAILED: no origin remote — nothing to mirror to", file=sys.stderr)
        raise SystemExit(3)
    print(f"gate 0: origin = {remote.stdout.strip().split('@')[-1]}")

    local = local_chain_head()
    print(f"gate 1: local chain VALID through seq={local['seq']} ({local['count']} entries)")

    mirror = mirror_head()
    gate_2_mirror_extends(local, mirror)

    # Только trust-пути в staging: чистим index выборочно, не трогая рабочий каталог
    _git(["reset", "--quiet"])
    _git(["add", *TRUST_PATHS])
    gate_3_only_trust_paths_staged()

    # diff --cached --quiet: код 1 = есть изменения, 0 = нет
    changed = _git(["diff", "--cached", "--quiet"], check=False).returncode == 1

    if not changed:
        print("mirror already up to date")
        branch_protection_reminder()
        return

    pushed = _git(["diff", "--cached", "--stat"]).stdout.strip()
    print(f"would push:\n{pushed}" if args.dry_run else f"pushing:\n{pushed}")

    if args.dry_run:
        branch_protection_reminder()
        return

    head = local_chain_head()
    _git(["commit", "-m", f"Ledger mirror: append history through seq={head['seq']}"])
    _git(["push", "origin", "master"])
    print(f"mirrored: local head seq={head['seq']} is now on the remote")
    branch_protection_reminder()


if __name__ == "__main":
    main()
