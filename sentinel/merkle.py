"""Merkle-аккумулятор в стиле RFC 6962 (Certificate Transparency).

Листья — entry_hash записей хеш-цепочки в порядке seq. Аккумулятор
даёт:

- корень дерева для любого префикса (tree head);
- доказательство включения (inclusion proof) листа в дерево;
- доказательство согласованности (consistency proof) между двумя
  tree heads — что дерево размера N является продолжением дерева
  размера M.

Доказательства проверяются независимо (см. verifier/), поэтому внешний
аудитор может убедиться, что конкретная квитанция входит в подписанный
tree head, а опубликованные tree heads не переписывали историю.

Формат хеширования (RFC 6962 §2.1):
- лист:  SHA256(0x00 || leaf)
- узел:  SHA256(0x01 || left || right)
"""
from __future__ import annotations

import hashlib
from typing import Optional

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(entry_hash: str) -> str:
    """Хеш листа Merkle-дерева из entry_hash записи цепочки."""
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(entry_hash)).hexdigest()


def node_hash(left: str, right: str) -> str:
    """Хеш внутреннего узла из двух дочерних (hex)."""
    return hashlib.sha256(
        NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


def _largest_power_of_two_less_than(n: int) -> int:
    """Наибольшая степень двойки, меньшая n (n >= 2)."""
    k = 1

    while k * 2 < n:
        k *= 2

    return k


class MerkleAccumulator:
    """Append-only Merkle-дерево над списком листьев.

    Держит листья в памяти (восстанавливается из журнала при старте);
    корень и доказательства вычисляются по списку. Для прототипного
    леджера это O(n) по памяти и O(n) на построение, что приемлемо:
    тысячи записей — доли мегабайта.
    """

    def __init__(self, leaves: Optional[list[str]] = None):
        # leaves — уже листовой хеш (leaf_hash от entry_hash)
        self._leaves: list[str] = list(leaves or [])

    @property
    def tree_size(self) -> int:
        return len(self._leaves)

    def append(self, leaf: str) -> None:
        self._leaves.append(leaf)

    def leaf_at(self, index: int) -> str:
        return self._leaves[index]

    # === Корни ===

    def root_hash(self, size: Optional[int] = None) -> Optional[str]:
        """MTH (Merkle Tree Head) первых ``size`` листьев.

        None для пустого дерева. RFC 6962: MTH одного листа — сам лист;
        MTH(n) = H(0x01 || MTH(k) || MTH(k+1..n)), k — наибольшая степень
        двойки меньше n.
        """
        if size is None:
            size = len(self._leaves)

        if size <= 0 or size > len(self._leaves):
            return None

        return self._mth(0, size)

    def _mth(self, start: int, end: int) -> str:
        """MTH среза листьев [start, end) (end - start >= 1)."""
        n = end - start

        if n == 1:
            return self._leaves[start]

        k = _largest_power_of_two_less_than(n)
        left = self._mth(start, start + k)
        right = self._mth(start + k, end)
        return node_hash(left, right)

    # === Доказательство включения (RFC 6962 §2.1.1) ===

    def inclusion_proof(
        self, index: int, size: Optional[int] = None
    ) -> Optional[list[dict[str, str]]]:
        """Доказательство включения листа ``index`` в дерево размера ``size``.

        Возвращает список {"hash", "direction"} от листа к корню;
        direction = "left"|"right" — с какой стороны брат. None, если
        индекс вне диапазона.
        """
        if size is None:
            size = len(self._leaves)

        if not (0 <= index < size <= len(self._leaves)):
            return None

        return self._path(index, 0, size)

    def _path(self, index: int, start: int, end: int) -> list[dict[str, str]]:
        n = end - start

        if n == 1:
            return []

        k = _largest_power_of_two_less_than(n)

        if index < k:
            # Лист в левом поддереве; корень правого — правый брат
            return self._path(index, start, start + k) + [
                {"hash": self._mth(start + k, end), "direction": "right"}
            ]

        # Лист в правом поддереве; корень левого — левый брат
        return self._path(index - k, start + k, end) + [
            {"hash": self._mth(start, start + k), "direction": "left"}
        ]

    # === Доказательство согласованности (RFC 6962 §2.1.2) ===

    def consistency_proof(
        self, old_size: int, new_size: Optional[int] = None
    ) -> Optional[list[str]]:
        """Доказательство, что дерево ``new_size`` продолжает ``old_size``.

        Возвращает список хешей (SUBPROOF из RFC 6962) или None при
        некорректных размерах.
        """
        if new_size is None:
            new_size = len(self._leaves)

        if not (0 <= old_size <= new_size <= len(self._leaves)):
            return None

        if old_size == new_size:
            return []

        if old_size == 0:
            return []

        return self._subproof(old_size, 0, new_size, complete=True)

    def _subproof(
        self, m: int, start: int, end: int, complete: bool
    ) -> list[str]:
        n = end - start

        if m == n:
            return [] if complete else [self._mth(start, end)]

        k = _largest_power_of_two_less_than(n)

        if m <= k:
            return self._subproof(m, start, start + k, complete) + [
                self._mth(start + k, end)
            ]

        return self._subproof(m - k, start + k, end, False) + [
            self._mth(start, start + k)
        ]


# === Независимая проверка доказательств ===


def verify_inclusion(
    entry_hash: str,
    index: int,
    tree_size: int,
    root_hash: str,
    proof: list[dict[str, str]],
) -> bool:
    """Проверяет inclusion proof (RFC 6962 §2.1.1).

    proof — список {"hash", "direction"} от листа к корню.
    """
    if index < 0 or tree_size <= 0 or index >= tree_size:
        return False

    fn = leaf_hash(entry_hash)

    for step in proof:
        sibling = step.get("hash", "")
        direction = step.get("direction")

        if direction == "left":
            fn = node_hash(sibling, fn)
        elif direction == "right":
            fn = node_hash(fn, sibling)
        else:
            return False

    return fn == root_hash


def verify_consistency(
    old_size: int,
    old_root: Optional[str],
    new_size: int,
    new_root: str,
    proof: list[str],
) -> bool:
    """Проверяет consistency proof (RFC 6962 §2.1.2, формат SUBPROOF).

    Доказывает, что дерево размера ``new_size`` с корнем ``new_root``
    является продолжением дерева размера ``old_size`` с корнем
    ``old_root`` (префикс не переписан).

    Проверка рекурсивно восстанавливает ОБА корня из доказательства,
    зеркаля структуру SUBPROOF: для поддеревьев, целиком лежащих вне
    старого дерева или целиком внутри него вне спуска, хеш берётся из
    доказательства; на пути спуска хеши комбинируются. В конце
    сверяются и ``new_root``, и ``old_root``.

    Когда ``old_size`` — степень двойки, старое дерево является полным
    выровненным поддеревом и его корень используется как доверенная
    отправная точка (как в RFC: seed = old_root); доказательство в этом
    случае подтверждает именно ``new_root``.
    """
    if old_size < 0 or new_size < old_size:
        return False

    if old_size == 0:
        # Пустое дерево тривиально согласовано с любым
        return True

    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root

    if old_root is None:
        return False

    pos = 0

    def rec(start: int, end: int, old_count: int, complete: bool) -> tuple[str, str]:
        """Возвращает (хеш нового поддерева, хеш старого поддерева)."""
        nonlocal pos
        n = end - start

        if old_count == n:
            # Поддерево целиком внутри старого дерева
            if complete:
                # Это и есть всё старое дерево D[0:old_size]; его хеш —
                # доверенный old_root (случай old_size = степень двойки)
                return old_root, old_root  # type: ignore[return-value]

            if pos >= len(proof):
                raise ValueError("proof too short")

            h = proof[pos]
            pos += 1
            return h, h

        k = _largest_power_of_two_less_than(n)

        if old_count <= k:
            left_new, left_old = rec(start, start + k, old_count, complete)

            if pos >= len(proof):
                raise ValueError("proof too short")

            right = proof[pos]
            pos += 1
            return node_hash(left_new, right), left_old

        right_new, right_old = rec(start + k, end, old_count - k, False)

        if pos >= len(proof):
            raise ValueError("proof too short")

        left = proof[pos]
        pos += 1
        return node_hash(left, right_new), node_hash(left, right_old)

    try:
        new_h, old_h = rec(0, new_size, old_size, True)
    except ValueError:
        return False

    return pos == len(proof) and new_h == new_root and old_h == old_root
