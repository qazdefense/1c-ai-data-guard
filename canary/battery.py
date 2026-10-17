"""Набор атак на шлюз и поиск утечки канареек. Работает с любым шлюзом: функция call(метод, цель) -> (статус, текст ответа)."""
from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Callable

from dataguard.scanner import leak_check

Call = Callable[[str, str], "tuple[int, str]"]
ENTITY = "Catalog_Контрагенты"
IIN_FIELD = "ИдентификационныйКодЛичности"


def fake_upstream(rows: list[dict[str, Any]], seen: list[str]) -> Callable[[str], "tuple[int, bytes]"]:
    """Поддельный OData: возвращает канарейки как есть, понимает equality-фильтры, эхом возвращает ошибку по слову boom."""

    def fetch(target: str) -> "tuple[int, bytes]":
        seen.append(target)
        parts = urllib.parse.urlsplit(target)
        q = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        if "boom" in q.get("$filter", ""):
            return 500, ("Ошибка в запросе: " + q["$filter"]).encode("utf-8")
        data = list(rows)
        flt = q.get("$filter")
        if flt:
            for clause in re.split(r"\s+and\s+", flt):
                m = re.match(r"^(\S+) eq '(.*)'$", clause.strip())
                if m:
                    data = [r for r in data if str(r.get(m.group(1))) == m.group(2).replace("''", "'")]
        top = int(q.get("$top", "100"))
        if parts.path.endswith("/$count"):
            return 200, str(len(data)).encode("ascii")
        return 200, json.dumps({"odata.metadata": "http://internal/secret-host/$metadata", "value": data[:top]}, ensure_ascii=False).encode("utf-8")

    return fetch


def attacks(rows: list[dict[str, Any]], token: str = "") -> list[tuple[str, str, str]]:
    """(метка, метод, цель). token - токен из первого ответа шлюза для проверки поиска по токену."""
    e = urllib.parse.quote(ENTITY)
    real = rows[0][IIN_FIELD]
    name = rows[0]["Description"]
    q = urllib.parse.quote
    return [
        ("список", "GET", f"/{e}"),
        ("список с top в миллиард", "GET", f"/{e}?$top=1000000000"),
        ("количество", "GET", f"/{e}/$count"),
        ("поле вне политики", "GET", f"/{e}?$select=Комментарий"),
        ("телефон вне политики", "GET", f"/{e}?$select=Телефон,Email,РасчетныйСчет,ПаспортныеДанные"),
        ("фильтр по реальному ИИН", "GET", f"/{e}?$filter={q(IIN_FIELD + ' eq ' + repr(real))}"),
        ("фильтр по реальному ИИН в двойных кавычках", "GET", f"/{e}?$filter={q(IIN_FIELD + ' eq ' + chr(34) + real + chr(34))}"),
        ("фильтр по имени без токена", "GET", f"/{e}?$filter={q('Description eq ' + repr(name))}"),
        ("подстрока в имени", "GET", f"/{e}?$filter={q('substringof(' + repr(name.split()[0]) + ',Description)')}"),
        ("неизвестный токен", "GET", f"/{e}?$filter={q(IIN_FIELD + ' eq ' + repr('[[iin:AAAAAAAAAA]]'))}"),
        ("фильтр или-условием", "GET", f"/{e}?$filter={q(IIN_FIELD + ' eq ' + repr('x') + ' or Description eq ' + repr('y'))}"),
        ("ИИН внутри поля pass", "GET", f"/{e}?$filter={q('Number eq ' + repr('код ' + real))}"),
        ("сортировка по защищаемому полю", "GET", f"/{e}?$orderby=Description"),
        ("раскрытие связей", "GET", f"/{e}?$expand=Банк"),
        ("метаданные", "GET", "/$metadata"),
        ("пакетный запрос", "GET", "/$batch"),
        ("чужой набор", "GET", "/Catalog_Пользователи"),
        ("выход из пути", "GET", f"/{e}/../Catalog_Пользователи"),
        ("двойной слеш", "GET", f"//{e}"),
        ("запись", "POST", f"/{e}"),
        ("удаление", "DELETE", f"/{e}"),
        ("формат xml", "GET", f"/{e}?$format=xml"),
        ("лишний параметр", "GET", f"/{e}?$inlinecount=allpages"),
        ("эхо ошибки источника", "GET", f"/{e}?$filter={q('Number eq ' + repr('boom ' + name))}"),
    ] + ([("поиск по токену", "GET", f"/{e}?$filter={q(IIN_FIELD + ' eq ' + repr(token))}")] if token else [])


def _ascii(target: str) -> str:
    """Не-ASCII и пробелы кодируются процентами: так запрос можно отправить по HTTP (шлюз декодирует сам)."""
    return re.sub(r"[^!-~]", lambda m: urllib.parse.quote(m.group(0)), target)


def run_battery(call: Call, rows: list[dict[str, Any]]) -> list[tuple[str, int, str]]:
    first_status, first_text = call("GET", f"/{urllib.parse.quote(ENTITY)}")
    token = ""
    if first_status == 200:
        m = re.search(r"\[\[iin:[A-Z2-7]{10}\]\]", first_text)
        token = m.group(0) if m else ""
    results = []
    for label, method, target in attacks(rows, token):
        status, text = call(method, _ascii(target))
        results.append((label, status, text))
    return results


def find_leaks(results: list[tuple[str, int, str]], secrets: list[tuple[str, str]], extra: tuple[str, ...] = ()) -> list[tuple[str, str, str]]:
    """Какие канарейки вышли открытым текстом: (метка запроса, класс, значение). extra - журнал шлюза и прочие тексты."""
    found = []
    for label, _status, text in results:
        for cls, value in leak_check(text, secrets):
            found.append((label, cls, value))
    for text in extra:
        for cls, value in leak_check(text, secrets):
            found.append(("журнал", cls, value))
    return found
