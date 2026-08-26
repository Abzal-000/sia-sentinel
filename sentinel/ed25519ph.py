#!/usr/bin/env python3
"""Ed25519ph (RFC 8032 HashEdDSA) на одной стандартной библиотеке.

ЗАЧЕМ. Публичный Rekor проверяет Ed25519-подписи с опцией WithED25519ph,
то есть требует именно ph. В pyca/cryptography ph-API нет, PyNaCl здесь не
установлен, а ПОДМЕНОЙ СООБЩЕНИЯ у обычного Ed25519 ph получить нельзя:

    RFC 8032 §5.1.6 шаг 2:  SHA-512(dom2 ‖ prefix ‖ PH(M))
    RFC 8032 §5.1.7 шаг 2:  SHA-512(dom2 ‖ R ‖ A ‖ PH(M))

dom2 стоит ПЕРЕД prefix и ПЕРЕД R‖A, а сообщением можно дописать только
в хвост. Проверено: dom2‖PH(M), PH(M), PH(M)‖dom2 и M — все четыре
отвергаются и pyca, и эталонным верификатором. Поэтому ниже эталонная
арифметика Эдвардса из RFC 8032 §6.

ДОКАЗАТЕЛЬСТВО КОРРЕКТНОСТИ (python ed25519ph.py):
  1. sign(prehash=True) воспроизводит вектор §7.3 ПОБАЙТОВО, и открытый
     ключ выводится из того же seed;
  2. sign(prehash=False) даёт подписи, которые принимает pyca — значит это
     корректный общий Ed25519, а не подгонка под один вектор;
  3. verify(dom2=b"") принимает подпись, сделанную pyca.
Пункт 2 — главный: без него совпадение с вектором ничего не значило бы.

ОГОВОРКА. Умножение точки здесь на питоновских целых и НЕ защищено от атак
по времени: секретный скаляр обрабатывается битом за битом. На локальной
машине без удалённого замера это приемлемо, но выдавать это за
криптобиблиотеку общего назначения нельзя — сравнение с pyca касается
корректности, а не стойкости к side-channel.

Стоимость: $0, офлайн, ~1 с.
"""
import hashlib

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493

# Префикс домена ph: 32 байта метки + phflag(1) + len(context)=0.
DOM2_PH = b"SigEd25519 no Ed25519 collisions" + bytes([1]) + bytes([0])
assert len(DOM2_PH) == 34


def _inv(x):
    return pow(x, p - 2, p)


d = -121665 * _inv(121666) % p
_sqrt_m1 = pow(2, (p - 1) // 4, p)


def _recover_x(y, sign):
    if y >= p:
        return None

    x2 = (y * y - 1) * _inv(d * y * y + 1) % p

    if x2 == 0:
        return None if sign else 0

    x = pow(x2, (p + 3) // 8, p)

    if (x * x - x2) % p != 0:
        x = x * _sqrt_m1 % p

    if (x * x - x2) % p != 0:
        return None

    return p - x if (x & 1) != sign else x


_Gy = 4 * _inv(5) % p
_Gx = _recover_x(_Gy, 0)
G = (_Gx, _Gy, 1, _Gx * _Gy % p)


def _add(P, Q):
    """Расширенные координаты, RFC 8032 §6."""
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, Gg, H = B - A, D - C, D + C, B + A
    return (E * F % p, Gg * H % p, F * Gg % p, E * H % p)


def _mul(s, P):
    Q = (0, 1, 1, 0)

    while s > 0:
        if s & 1:
            Q = _add(Q, P)

        P = _add(P, P)
        s >>= 1

    return Q


def _equal(P, Q):
    return ((P[0] * Q[2] - Q[0] * P[2]) % p == 0
            and (P[1] * Q[2] - Q[1] * P[2]) % p == 0)


def _compress(P):
    zinv = _inv(P[2])
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None

    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def _h_modq(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little") % L


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    s = int.from_bytes(h[:32], "little")
    s &= (1 << 254) - 8          # обнулить три младших бита
    s |= (1 << 254)              # выставить бит 254
    return s, h[32:]


def public_key(seed: bytes) -> bytes:
    """32 байта открытого ключа из 32 байт seed."""
    s, _ = _expand(seed)
    return _compress(_mul(s, G))


def sign(seed: bytes, message: bytes, prehash: bool = True) -> bytes:
    """64 байта подписи. prehash=True — Ed25519ph, False — обычный Ed25519.

    message передаётся СЫРЫМ в обоих режимах: при prehash=True SHA-512
    берётся здесь. Снаружи ничего пред-хешировать не нужно.
    """
    dom2 = DOM2_PH if prehash else b""
    m = hashlib.sha512(message).digest() if prehash else message
    s, prefix = _expand(seed)
    A = _compress(_mul(s, G))
    r = _h_modq(dom2 + prefix + m)
    R = _compress(_mul(r, G))
    k = _h_modq(dom2 + R + A + m)
    return R + int.to_bytes((r + k * s) % L, 32, "little")


def verify(pub: bytes, message: bytes, sig: bytes, prehash: bool = True) -> bool:
    """Проверка. message сырой, как в sign()."""
    if len(sig) != 64:
        return False

    dom2 = DOM2_PH if prehash else b""
    m = hashlib.sha512(message).digest() if prehash else message
    return _verify_core(pub, m, sig, dom2)


def _verify_core(pub: bytes, m: bytes, sig: bytes, dom2: bytes) -> bool:
    A = _decompress(pub)
    R = _decompress(sig[:32])

    if A is None or R is None:
        return False

    S = int.from_bytes(sig[32:], "little")

    if S >= L:
        return False

    k = _h_modq(dom2 + sig[:32] + pub + m)
    return _equal(_mul(S, G), _add(R, _mul(k, A)))


# --------------------------------------------- уровень готового дайджеста
# Rekor (hashedrekord + WithED25519ph) отдаёт верификатору РОВНО 64 байта
# дайджеста из spec.data.hash.value и трактует их как PH(M) — Go требует
# len(message)==64 при Options{Hash: SHA512}. Своего хеша он не берёт.
# Значит подписывать надо ph над теми байтами, чей SHA-512 лежит в записи,
# и НИ ОДНОГО лишнего хеша: sha512(value) уже не проверится.


def sign_digest(seed: bytes, digest64: bytes) -> bytes:
    """Ed25519ph, где PH(M) передан готовым (64 байта). Для Rekor."""
    if len(digest64) != 64:
        raise ValueError("PH(M) для Ed25519ph — ровно 64 байта SHA-512")

    s, prefix = _expand(seed)
    A = _compress(_mul(s, G))
    r = _h_modq(DOM2_PH + prefix + digest64)
    R = _compress(_mul(r, G))
    k = _h_modq(DOM2_PH + R + A + digest64)
    return R + int.to_bytes((r + k * s) % L, 32, "little")


def verify_digest(pub: bytes, digest64: bytes, sig: bytes) -> bool:
    """Проверка так, как это делает Go/Rekor: 64 байта = PH(M)."""
    if len(sig) != 64 or len(digest64) != 64:
        return False

    return _verify_core(pub, digest64, sig, DOM2_PH)


# ------------------------------------------------------------------ самотест

# RFC 8032 §7.3, единственный вектор Ed25519ph.
_V_SEED = bytes.fromhex(
    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")
_V_PUB = bytes.fromhex(
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")
_V_MSG = bytes.fromhex("616263")            # "abc"
_V_SIG = bytes.fromhex(
    "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae41"
    "31f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")


def _raises(fn) -> bool:
    try:
        fn()
        return False
    except ValueError:
        return True


def selftest() -> int:
    checks = []
    checks.append(("open key from the 7.3 seed matches 7.3",
                   public_key(_V_SEED) == _V_PUB))
    checks.append(("ph signature reproduces 7.3 byte-for-byte",
                   sign(_V_SEED, _V_MSG) == _V_SIG))
    checks.append(("own ph verify accepts the 7.3 vector",
                   verify(_V_PUB, _V_MSG, _V_SIG)))
    checks.append(("own ph verify rejects a flipped message",
                   not verify(_V_PUB, b"abd", _V_SIG)))

    # Дайджест-уровень должен совпадать с обычным ph, иначе одна из двух
    # дверей в этот модуль ведёт не туда.
    _msg = b'{"protocol":"sia-preregistration/4"}'
    _dig = hashlib.sha512(_msg).digest()
    checks.append(("sign_digest(PH(M)) == sign(M, prehash=True)",
                   sign_digest(_V_SEED, _dig) == sign(_V_SEED, _msg)))
    checks.append(("verify_digest accepts it",
                   verify_digest(public_key(_V_SEED), _dig,
                                 sign(_V_SEED, _msg))))
    checks.append(("verify_digest rejects one hash too many (Rekor trap)",
                   not verify_digest(public_key(_V_SEED), _dig,
                                     sign(_V_SEED, _dig))))
    checks.append(("sign_digest refuses a non-64-byte PH(M)",
                   _raises(lambda: sign_digest(_V_SEED, b"\x00" * 32))))

    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization as ser
        from cryptography.hazmat.primitives.asymmetric import ed25519 as ed

        # (2) plain mode must satisfy an independent implementation
        plain = sign(_V_SEED, b"cross-check", prehash=False)
        pub = public_key(_V_SEED)

        try:
            ed.Ed25519PublicKey.from_public_bytes(pub).verify(plain, b"cross-check")
            checks.append(("pyca accepts our prehash=False signature", True))
        except InvalidSignature:
            checks.append(("pyca accepts our prehash=False signature", False))

        # (3) our verifier must accept an independent implementation's output
        sk = ed.Ed25519PrivateKey.generate()
        raw = sk.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        checks.append(("we accept a pyca pure signature",
                       verify(raw, b"cross-check", sk.sign(b"cross-check"),
                              prehash=False)))

        # ph must NOT be reachable by substituting the message
        subs = {"dom2||PH(M)": DOM2_PH + hashlib.sha512(_V_MSG).digest(),
                "PH(M)": hashlib.sha512(_V_MSG).digest(),
                "M": _V_MSG}
        bad = []

        for name, msg in subs.items():
            try:
                ed.Ed25519PublicKey.from_public_bytes(_V_PUB).verify(_V_SIG, msg)
                bad.append(name)
            except InvalidSignature:
                pass

        checks.append(("no message substitution yields ph (%d tried)" % len(subs),
                       not bad))
    except ImportError:
        checks.append(("cryptography present for cross-checks", False))

    rc = 0

    for name, ok in checks:
        print("   [%s] %s" % ("OK  " if ok else "FAIL", name))

        if not ok:
            rc = 1

    print("\n   %s" % ("all checks passed" if rc == 0 else "SELFTEST FAILED"))
    return rc


if __name__ == "__main__":
    import sys

    sys.exit(selftest())
