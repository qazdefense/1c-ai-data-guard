"""Проверка и генерация идентификаторов с контрольными разрядами: Казахстан (ИИН/БИН, IBAN) и Россия (ИНН, СНИЛС, ОГРН)."""
from __future__ import annotations

import datetime as _dt
import random as _random
from typing import Optional

# ---------- Казахстан: ИИН / БИН ----------
_IIN_W1 = tuple(range(1, 12))
_IIN_W2 = (3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 2)


def kz_control_digit(first11: str) -> Optional[int]:
    """Контрольный разряд ИИН/БИН по первым 11 цифрам; None, если номер с таким началом не выдается."""
    digits = [int(c) for c in first11]
    k = sum(d * w for d, w in zip(digits, _IIN_W1)) % 11
    if k == 10:
        k = sum(d * w for d, w in zip(digits, _IIN_W2)) % 11
    return None if k == 10 else k


def _kz_date_ok(yymm_dd: str) -> bool:
    mm = int(yymm_dd[2:4])
    return 1 <= mm <= 12


def is_kz_iin(value: str) -> bool:
    """Физлицо: 12 цифр, месяц рождения 01-12, 7-й разряд 1-6 (век и пол), верная контрольная цифра."""
    if len(value) != 12 or not value.isdigit():
        return False
    if not _kz_date_ok(value) or value[6] not in "123456" or int(value[4:6]) > 31 or int(value[4:6]) < 1:
        return False
    return kz_control_digit(value[:11]) == int(value[11])


def is_kz_bin(value: str) -> bool:
    """Юрлицо и ИП: 12 цифр, месяц регистрации 01-12, 5-й разряд 4/5/6 (тип), верная контрольная цифра."""
    if len(value) != 12 or not value.isdigit():
        return False
    if not _kz_date_ok(value) or value[4] not in "456":
        return False
    return kz_control_digit(value[:11]) == int(value[11])


def is_kz_iin_or_bin(value: str) -> bool:
    return is_kz_iin(value) or is_kz_bin(value)


def make_kz_iin(birth: _dt.date, female: bool, rng: _random.Random) -> str:
    """Синтетический ИИН с верной контрольной цифрой (выдуманный, но структурно допустимый)."""
    century = {18: (1, 2), 19: (3, 4), 20: (5, 6)}[birth.year // 100]
    head = f"{birth.year % 100:02d}{birth.month:02d}{birth.day:02d}{century[1 if female else 0]}"
    while True:
        first11 = head + f"{rng.randrange(10000):04d}"
        k = kz_control_digit(first11)
        if k is not None:
            return first11 + str(k)


def make_kz_bin(yymm: str, rng: _random.Random, kind: str = "4", sub: str = "0") -> str:
    """Синтетический БИН: ГГММ, тип (4 - юрлицо-резидент, 5 - филиал, 6 - ИП), подтип, порядковый номер."""
    while True:
        first11 = yymm + kind + sub + f"{rng.randrange(100000):05d}"
        k = kz_control_digit(first11)
        if k is not None:
            return first11 + str(k)


# ---------- IBAN (Казахстан KZ, ISO 7064 mod 97-10) ----------
def _iban_num(s: str) -> int:
    return int("".join(str(int(c, 36)) for c in s))


def is_iban(value: str) -> bool:
    v = value.replace(" ", "").upper()
    if not (15 <= len(v) <= 34) or not v.isalnum() or not v[:2].isalpha() or not v[2:4].isdigit():
        return False
    return _iban_num(v[4:] + v[:4]) % 97 == 1


def is_kz_iban(value: str) -> bool:
    v = value.replace(" ", "").upper()
    return len(v) == 20 and v.startswith("KZ") and is_iban(v)


def make_kz_iban(rng: _random.Random, bank_code: str = "999") -> str:
    """Синтетический IBAN: KZ + контрольные цифры + код банка + 13 символов счета (код банка 999 не выдан реальному банку)."""
    alphabet = "0123456789"
    bban = bank_code + "".join(rng.choice(alphabet) for _ in range(13))
    check = 98 - _iban_num(bban + "KZ00") % 97
    return f"KZ{check:02d}{bban}"


# ---------- Россия: ИНН, СНИЛС, ОГРН ----------
_INN10 = (2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN12_A = (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)
_INN12_B = (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)


def _inn_digit(digits: list[int], weights: tuple[int, ...]) -> int:
    return sum(d * w for d, w in zip(digits, weights)) % 11 % 10


def is_ru_inn(value: str) -> bool:
    if not value.isdigit():
        return False
    d = [int(c) for c in value]
    if len(d) == 10:
        return _inn_digit(d, _INN10) == d[9]
    if len(d) == 12:
        return _inn_digit(d, _INN12_A) == d[10] and _inn_digit(d, _INN12_B) == d[11]
    return False


def make_ru_inn(rng: _random.Random, legal: bool = True) -> str:
    if legal:
        d = [rng.randrange(10) for _ in range(9)]
        d.append(_inn_digit(d, _INN10))
    else:
        d = [rng.randrange(10) for _ in range(10)]
        d.append(_inn_digit(d, _INN12_A))
        d.append(_inn_digit(d, _INN12_B))
    return "".join(map(str, d))


def _snils_check(nine: str) -> int:
    s = sum(int(c) * w for c, w in zip(nine, range(9, 0, -1)))
    while s > 101:
        s %= 101
    return 0 if s in (100, 101) else s


def is_ru_snils(value: str) -> bool:
    v = "".join(c for c in value if c.isdigit())
    return len(v) == 11 and _snils_check(v[:9]) == int(v[9:])


def make_ru_snils(rng: _random.Random) -> str:
    nine = f"{rng.randrange(1_001_998, 999_999_999):09d}"
    return nine + f"{_snils_check(nine):02d}"


def is_ru_ogrn(value: str) -> bool:
    if not value.isdigit():
        return False
    if len(value) == 13:
        return int(value[:12]) % 11 % 10 == int(value[12])
    if len(value) == 15:
        return int(value[:14]) % 13 % 10 == int(value[14])
    return False


def make_ru_ogrn(rng: _random.Random, sole: bool = False) -> str:
    if sole:
        head = "3" + "".join(str(rng.randrange(10)) for _ in range(13))
        return head + str(int(head) % 13 % 10)
    head = "1" + "".join(str(rng.randrange(10)) for _ in range(11))
    return head + str(int(head) % 11 % 10)
