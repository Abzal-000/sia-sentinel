"""Holdout под контролем аудитора (п.8) — сторона внешнего аудитора.

Роли (см. docs/holdout-design.md): АУДИТОРОМ здесь может быть только
посторонний без доли. Инструмент не требует и не должен требовать ключей
оператора: независимость обеспечивается тем, что манифест holdout
подписан ключом аудитора, а элементы раскрываются только после записи.

Три команды:

    make    — аудитор формирует holdout: элементы уходят в секретное
              хранилище (остаётся у аудитора), наружу — только подписанный
              манифест {n, dataset_sha256, created_at, audit_pubkey}.
    reveal  — после записи: извлечь элементы для раскрытия; sha256
              сверяется с манифестом внутри хранилища.
    verify  — для любой третьей стороны: элементы соответствуют
              подписанному манифесту (подпись + хеш).

Формат элемента — как в датасете флоу: {label, prompt, expect_contains};
хеш — та же схема, что у записи №1 (sha256 от join «prompt|expect»),
поэтому оператор сверяет полученное той же функцией, что и свой датасет.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import sys
import tempfile
import datetime as _dt
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.exceptions import InvalidSignature

HOLDOUT_PROTOCOL = "sia-holdout/1"
# Минимум, при котором δ=5 п.п. проходит MDD-гейт по правилу спеки §1.1
# (10% планировочный пол дискордантности; вывод тот же, что у маяка).
RECOMMENDED_N_FOR_DELTA_5PP = 314


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def dataset_sha256(items: list[dict[str, Any]]) -> str:
    """Хеш элементов — схема записи №1: sha256 от join «prompt|expect»."""
    joined = "\n".join(
        f"{item.get('prompt', '')}|{item.get('expect_contains', '')}"
        for item in items
    )
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _load_items(path: Path) -> list[dict[str, Any]]:
    """JSONL или JSON-массив элементов {label, prompt, expect_contains}."""
    text = path.read_text(encoding="utf-8-sig").strip()

    if path.suffix == ".json":
        items = json.loads(text)
    else:
        items = [json.loads(line) for line in text.splitlines() if line.strip()]

    if not isinstance(items, list) or not items:
        raise ValueError(f"{path}: expected a non-empty list of holdout items")

    for index, item in enumerate(items):
        prompt = (item.get("prompt") or "").strip()
        expect = (item.get("expect_contains") or "").strip()
        if not prompt or not expect:
            raise ValueError(
                f"item {index}: 'prompt' and 'expect_contains' must be non-empty "
                "(an unchecked item verifies nothing — the same rule as the audit dataset)"
            )

    return items


# --- Ключи аудитора (НЕ оператора) -------------------------------------------


def load_or_create_key(seed: Optional[str] = None) -> tuple[Ed25519PrivateKey, str]:
    """Ключ аудитора: hex-сид (детерминированный) или новый случайный.

    Возвращает (private, seed_hex). Сид печатается один раз при создании;
    держать так же бережно, как RECEIPT_SIGNING_KEY, — потерянный ключ
    обрывает доверие ко всем манифестам аудитора.
    """
    if seed:
        material = bytes.fromhex(seed)
        if len(material) != 32:
            raise ValueError("key seed must be 64 hex chars (32 bytes)")
        return Ed25519PrivateKey.from_private_bytes(material), seed

    seed_hex = secrets.token_hex(32)
    return (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)),
        seed_hex,
    )


def _public_b64(private: Ed25519PrivateKey) -> str:
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _load_public(value: str) -> Ed25519PublicKey:
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32:
        raise ValueError("audit_pubkey must be base64 raw 32-byte Ed25519")
    return Ed25519PublicKey.from_public_bytes(raw)


def _manifest_body(manifest: dict[str, Any]) -> bytes:
    """То, что покрывает подпись аудитора (без самой подписи)."""
    return _canon(
        {
            "protocol": manifest["protocol"],
            "n": manifest["n"],
            "dataset_sha256": manifest["dataset_sha256"],
            "created_at": manifest["created_at"],
            "audit_pubkey": manifest["audit_pubkey"],
            "note": manifest.get("note"),
        }
    )


# --- Команды ------------------------------------------------------------------


def cmd_make(args: argparse.Namespace) -> int:
    items = _load_items(Path(args.source))
    private, seed_hex = load_or_create_key(args.key)
    created_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

    manifest = {
        "protocol": HOLDOUT_PROTOCOL,
        "n": len(items),
        "dataset_sha256": dataset_sha256(items),
        "created_at": created_at,
        "audit_pubkey": _public_b64(private),
        "note": args.note,
    }
    manifest["signature"] = base64.b64encode(
        private.sign(_manifest_body(manifest))
    ).decode("ascii")

    if len(items) < RECOMMENDED_N_FOR_DELTA_5PP:
        print(
            f"WARNING: n={len(items)} < {RECOMMENDED_N_FOR_DELTA_5PP}: at delta=5pp "
            "the MDD gate will block a non-inferior verdict (spec 1.1); the holdout "
            "is then evidence-for-consistency, not a second verdict."
        )

    manifest_path = Path(args.out)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    store_path = Path(args.store)
    store = {
        "protocol": HOLDOUT_PROTOCOL,
        "manifest": manifest,
        "items": items,
    }
    store_path.write_text(json.dumps(store, indent=2), encoding="utf-8")

    print(f"holdout manifest (public): {manifest_path}")
    print(f"secret store (KEEP PRIVATE until the record is published): {store_path}")
    print(f"n={manifest['n']}  dataset_sha256={manifest['dataset_sha256']}")
    if args.key is None:
        print(
            "NEW AUDITOR KEY SEED (store in a password manager, never in chat):\n"
            f"  hex, {len(seed_hex)} chars: {seed_hex[:4]}…{seed_hex[-4:]} (masked; "
            "full value printed once to a temp file for copy-paste)"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", prefix="holdout_key_", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(seed_hex + "\n")
            print(f"  full seed written to: {handle.name}")
    print(
        "Next: send ONLY the manifest to the operator; keep the store; reveal "
        "the items only after their record is published (step 4)."
    )
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    store = json.loads(Path(args.store).read_text(encoding="utf-8"))
    manifest = store.get("manifest") or {}

    if store.get("protocol") != HOLDOUT_PROTOCOL or manifest.get("protocol") != HOLDOUT_PROTOCOL:
        raise ValueError("store is not a sia-holdout/1 store")

    items = store.get("items") or []
    sha = dataset_sha256(items)

    if sha != manifest.get("dataset_sha256"):
        print("CORRUPT: store items do not match the manifest dataset_sha256", file=sys.stderr)
        return 1

    out = Path(args.out)
    with out.open("w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")

    print(f"revealed {len(items)} items -> {out}")
    print(f"dataset_sha256={sha} (matches the signed manifest)")
    print("Publish this file + the manifest; any third party runs 'verify'.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))

    if manifest.get("protocol") != HOLDOUT_PROTOCOL:
        print(f"unknown protocol: {manifest.get('protocol')!r}", file=sys.stderr)
        return 2

    try:
        public = _load_public(manifest["audit_pubkey"])
        public.verify(
            base64.b64decode(manifest["signature"], validate=True),
            _manifest_body(manifest),
        )
        signature_ok = True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        signature_ok = False

    items_ok: Optional[bool] = None
    if args.items:
        items = _load_items(Path(args.items))
        items_ok = dataset_sha256(items) == manifest.get("dataset_sha256")
        count_ok = len(items) == manifest.get("n")
    else:
        count_ok = None

    print(f"protocol:        {manifest.get('protocol')}")
    print(f"n:               {manifest.get('n')}")
    print(f"dataset_sha256:  {manifest.get('dataset_sha256')}")
    print(f"manifest sig:    {'VALID' if signature_ok else 'INVALID'}")
    if items_ok is not None:
        print(f"items match:     {'yes' if items_ok and count_ok else 'NO'}")
    print("VERDICT:", "VALID" if signature_ok and (items_ok is None or (items_ok and count_ok)) else "INVALID")
    ok = signature_ok and (items_ok is None or (items_ok and count_ok))
    return 0 if ok else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sia-holdout",
        description="Auditor-side holdout tool for SIA Proof-of-Savings (п.8).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    make = sub.add_parser("make", help="create a holdout: public signed manifest + secret store")
    make.add_argument("--source", required=True, help="JSONL/JSON file of {label, prompt, expect_contains} items")
    make.add_argument("--out", required=True, help="public manifest path (send to the operator)")
    make.add_argument("--store", required=True, help="secret store path (keep until reveal)")
    make.add_argument("--key", default=None, help="hex seed of the auditor key (64 hex chars); omit to generate")
    make.add_argument("--note", default=None, help="optional public note (e.g. intended pair)")
    make.set_defaults(func=cmd_make)

    reveal = sub.add_parser("reveal", help="after the record: extract items for publication")
    reveal.add_argument("--store", required=True, help="secret store from 'make'")
    reveal.add_argument("--out", required=True, help="JSONL file to publish")
    reveal.set_defaults(func=cmd_reveal)

    verify = sub.add_parser("verify", help="third party: manifest signature (+ items hash match)")
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--items", default=None, help="optional revealed items JSONL")
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
