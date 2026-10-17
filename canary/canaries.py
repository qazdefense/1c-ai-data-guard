"""Канарейки: выдуманные, но правдоподобные данные с верными контрольными цифрами. Если хоть одна оказалась в ответе открытым текстом, защита не работает."""
from __future__ import annotations

import datetime
import random
import uuid
from typing import Any

from dataguard import checksums as ck

_KZ_SURNAMES = ["Канарейкин", "Птичкин", "Щеглов", "Чижов", "Синицын", "Снегирев", "Соловьев", "Жаворонков"]
_KZ_NAMES = ["Арман", "Нурлан", "Айгуль", "Динара", "Берик", "Мадина", "Серик", "Алия"]


def make_canaries(profile: str = "kz", n: int = 12, seed: int = 20261018) -> dict[str, Any]:
    """rows - записи для поддельного источника; secrets - пары (класс, значение) для проверки утечки."""
    rng = random.Random(seed)
    rows: list[dict[str, Any]] = []
    secrets: list[tuple[str, str]] = []
    for i in range(n):
        name = f"{_KZ_SURNAMES[i % len(_KZ_SURNAMES)]}{'' if i < len(_KZ_SURNAMES) else i} {_KZ_NAMES[(i * 3) % len(_KZ_NAMES)]}"
        phone = f"+7 70{i % 9 + 1} {rng.randrange(100, 999)} {rng.randrange(10, 99)} {rng.randrange(10, 99)}"
        email = f"canary{i}.{rng.randrange(1000, 9999)}@example.kz"
        if profile == "kz":
            ident = ck.make_kz_iin(datetime.date(1960 + rng.randrange(40), 1 + rng.randrange(12), 1 + rng.randrange(28)), bool(i % 2), rng)
            account = ck.make_kz_iban(rng, "998")
            id_cls = "iin"
        else:
            ident = ck.make_ru_inn(rng, legal=False)
            account = "40817810" + "".join(str(rng.randrange(10)) for _ in range(12))
            id_cls = "inn"
        row = {
            "Ref_Key": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
            "Code": f"CANDG{i + 1:04d}",
            "Description": name,
            "ИдентификационныйКодЛичности": ident,
            "Телефон": phone,
            "Email": email,
            "РасчетныйСчет": account,
            "Комментарий": f"Звонил {name}, ИИН {ident}, тел. {phone}, писать на {email}",
            "Number": f"Счет № {i + 1} за {name.split()[0]} (код {ident})",
            "ПаспортныеДанные": f"Паспорт {rng.randrange(10**8, 10**9)} выдан {name}",
        }
        rows.append(row)
        secrets += [(id_cls, ident), ("phone", phone), ("email", email), ("account", account), ("name", name)]
    return {"profile": profile, "rows": rows, "secrets": secrets}
