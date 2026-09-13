#!/usr/bin/env bash
# Часовой ритуал леджера для крона (см. README «Anchoring from record №1»).
#
# Заменяет ручное «проверьте глазами» на автомат с двумя попытками:
#   1. scripts/ledger_health.py     — цепь/подписи/покрытие/Merkle/якорь
#   2. если единственная проблема — НЕПОКРЫТАЯ голова (нет чекпойнта или
#      якорного файла), scripts/anchor_checkpoint.py подписывает и публикует
#      чекпойнт текущей головы; затем health повторяется
#   3. повторный провал — АЛЕРТ (stderr + опционально ALERT_WEBHOOK_URL)
#
# Почему авто-якорь безопасен здесь: anchor_checkpoint.py отказывается без
# RECEIPT_SIGNING_KEY (exit 3) и публикует только через настроенные
# транспорты (файл/HTTP/Rekor-флаг). Что НЕ чинится само: битая цепь,
# невалидные подписи, рассинхрон Merkle — их алерт уходит человеку,
# потому что «автоматически пересечь» их — маскировка, а не починка.
#
# Код выхода крона: 0 — здоров (сразу или после авто-якоря), 1 — ЧЕЛОВЕК,
# 2 — ошибка окружения. Алерт дедуплицируется файлом-маркером: не спамить
# каждый час одной и той же проблемой; маркер чистится при выздоровлении.
#
# Установка (прод, из README):
#   0 * * * * cd /srv/sentinel && docker compose -f docker-compose.prod.yml \
#     exec -T sentinel bash scripts/cron_ledger.sh
# Локально (dev): bash scripts/cron_ledger.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HEALTH_SCRIPT="$REPO_ROOT/scripts/ledger_health.py"
ANCHOR_SCRIPT="$REPO_ROOT/scripts/anchor_checkpoint.py"
MARKER="${SIA_ALERT_MARKER:-$REPO_ROOT/.cache/ledger_alert_active}"

alert() {
    # $1 — флаг "новый" (true) или "повтор" (false), остальное — текст
    local is_new="$1"; shift
    echo "[cron_ledger] ALERT: $*" >&2

    if [[ -n "${ALERT_WEBHOOK_URL:-}" ]]; then
        # минимальный POST без внешних зависимостей крона
        if command -v curl >/dev/null 2>&1; then
            curl -fsS -m 10 -X POST "$ALERT_WEBHOOK_URL" \
                -H 'Content-Type: application/json' \
                -d "{\"text\": \"[sia-ledger] $*\"}" >/dev/null 2>&1 || true
        fi
    fi

    if [[ "$is_new" == "true" ]]; then
        mkdir -p "$(dirname "$MARKER")"
        date -u +"%Y-%m-%dT%H:%M:%SZ" > "$MARKER"
    fi
}

clear_alert() {
    if [[ -f "$MARKER" ]]; then
        rm -f "$MARKER"
        echo "[cron_ledger] recovered: alert marker cleared"
    fi
}

# --- 1. Первая проверка -------------------------------------------------------
OUT="$("${PYTHON:-python}" "$HEALTH_SCRIPT" 2>&1)"
RC=$?
echo "$OUT"

if [[ $RC -eq 0 ]]; then
    clear_alert
    exit 0
fi

if [[ $RC -eq 2 ]]; then
    alert true "ledger health cannot run (exit 2 — env/files)"
    exit 2
fi

# RC == 1: разбираем, чинабельно ли автоматически. Авто-якорь уместен ТОЛЬКО
# при «покрытие/якорь»-жалобах; любые INVALID/MISMATCH — человеку.
if ! echo "$OUT" | grep -Eq 'UNCOVERED|GAP|MISSING.*anchor|anchor: MISSING'; then
    alert true "ledger health failed, not auto-fixable: $(echo "$OUT" | tail -2 | tr '\n' ' ')"
    exit 1
fi

echo "[cron_ledger] coverage/anchor gap detected — auto-anchoring current head"
"${PYTHON:-python}" "$ANCHOR_SCRIPT"
ANCHOR_RC=$?

if [[ $ANCHOR_RC -ne 0 ]]; then
    alert true "auto-anchor failed (exit $ANCHOR_RC) — RECEIPT_SIGNING_KEY present?"
    exit 1
fi

# --- 3. Повторная проверка ----------------------------------------------------
OUT2="$("${PYTHON:-python}" "$HEALTH_SCRIPT" 2>&1)"
RC2=$?
echo "$OUT2"

if [[ $RC2 -eq 0 ]]; then
    clear_alert
    echo "[cron_ledger] auto-anchor fixed the gap; ledger healthy"
    exit 0
fi

alert true "ledger still unhealthy after auto-anchor: $(echo "$OUT2" | tail -2 | tr '\n' ' ')"
exit 1
