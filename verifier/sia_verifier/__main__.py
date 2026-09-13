"""CLI независимого верификатора аттестаций Proof-of-Savings.

Примеры::

    # Проверить аттестацию из файла (документ GET /v1/attestations/{id})
    python -m sia_verifier attestation.json

    # Проверить аттестацию + хеш-цепочку журнала
    python -m sia_verifier attestation.json --chain registry.jsonl

    # Проверить подпись чекпойнта (одиночный JSON или JSONL-журнал
    # снимков — проверяются ВСЕ строки, не только последняя)
    python -m sia_verifier attestation.json --checkpoint checkpoint.json

Код выхода: 0 — аттестация валидна, 1 — невалидна, 2 — ошибка ввода.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .core import verify_attestation, verify_chain, verify_checkpoint


def _load_json(path: Path) -> Any:
    # utf-8-sig: PowerShell `>`-редирект и notepad пишут BOM; соседние
    # инструменты пакета (rederive/replay/holdout) уже BOM-толерантны, и
    # файлы постороннего проходят тот же путь.
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    entries = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line:
            entries.append(json.loads(line))
    return entries


def _load_checkpoints(path: Path) -> list[dict[str, Any]]:
    """Чекпойнт-файл: одиночный JSON-объект или JSONL-журнал снимков.

    Журнал (registry пишет по строке-снимку на каждый чекпойнт) проверяется
    ЦЕЛИКОМ: подпись каждого снимка должна сойтись. Валидность только
    последнего снимка означала бы, что подписанную фиксацию середины
    истории можно подменить безнаказанно — журнал не слабее своего
    худшего элемента.
    """
    text = path.read_text(encoding="utf-8-sig")

    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        loaded = None

    if isinstance(loaded, dict):
        return [loaded]

    if isinstance(loaded, list):
        entries = loaded
    else:
        entries = _load_jsonl(path)

    if not entries or not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("checkpoint file must contain JSON checkpoint object(s)")

    return entries


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sia-verifier",
        description="Independent verifier for sia-attestation/1 Proof-of-Savings attestations.",
    )
    parser.add_argument(
        "attestation",
        type=Path,
        help="Path to the attestation document JSON (GET /v1/attestations/{id})",
    )
    parser.add_argument(
        "--chain",
        type=Path,
        default=None,
        help="Optional TrustChain ledger export (registry.jsonl) to verify the hash chain",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="Optional checkpoint JSON or JSONL journal of snapshots to verify against the issuer public key",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the verdict as JSON instead of human-readable text",
    )

    args = parser.parse_args(argv)

    try:
        attestation = _load_json(args.attestation)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read attestation file: {exc}", file=sys.stderr)
        return 2

    verdict = verify_attestation(attestation)
    result: dict[str, Any] = {"attestation": verdict.to_dict()}

    issuer_key = (attestation.get("issuer") or {}).get("public_key", "")
    attestation_id = attestation.get("attestation_id")

    if args.chain is not None:
        try:
            entries = _load_jsonl(args.chain)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: cannot read chain file: {exc}", file=sys.stderr)
            return 2

        chain_verdict = verify_chain(entries, attestation_id=attestation_id)
        result["chain"] = chain_verdict.to_dict()

    if args.checkpoint is not None:
        try:
            checkpoints = _load_checkpoints(args.checkpoint)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"error: cannot read checkpoint file: {exc}", file=sys.stderr)
            return 2

        checked = [verify_checkpoint(cp, issuer_key) for cp in checkpoints]
        result["checkpoint_valid"] = all(checked)
        result["checkpoint_count"] = len(checked)

    overall = verdict.valid
    if "chain" in result:
        overall = overall and result["chain"]["valid"]
        if result["chain"].get("contains_attestation") is False:
            overall = False
            result["chain"]["reason"] = (
                result["chain"].get("reason")
                or "attestation_id not found in the provided chain"
            )
    if "checkpoint_valid" in result:
        overall = overall and result["checkpoint_valid"]

    if args.json:
        result["valid"] = overall
        print(json.dumps(result, indent=2))
    else:
        print(f"spec:                 {attestation.get('spec')}")
        print(f"attestation_id:       {attestation_id}")
        print(f"receipt signature:    {'VALID' if verdict.receipt_signature_valid else 'INVALID'}")
        print(f"claim consistent:     {'yes' if verdict.claim_consistent else 'NO'}")
        if "chain" in result:
            chain = result["chain"]
            print(f"chain:                {'VALID' if chain['valid'] else 'INVALID'} ({chain['entries']} entries)")
            if chain.get("contains_attestation") is False:
                print("chain membership:     attestation NOT FOUND in chain")
        if "checkpoint_valid" in result:
            count = result.get("checkpoint_count", 1)

            if count > 1:
                status = "VALID" if result["checkpoint_valid"] else "INVALID"
                print(f"checkpoint signatures: {status} ({count} checked)")
            else:
                print(f"checkpoint signature: {'VALID' if result['checkpoint_valid'] else 'INVALID'}")
        for reason in verdict.reasons:
            print(f"  - {reason}")
        print(f"VERDICT: {'VALID' if overall else 'INVALID'}")

    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
