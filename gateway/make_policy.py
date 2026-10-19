"""Черновик политики шлюза из правил обезличивания и $metadata OData: безопасный по умолчанию.

  py -m gateway.make_policy --rules 1c\\rules\\kz.txt --metadata metadata.xml --profile kz --out my.policy.json
  py -m gateway.make_policy --rules 1c\\rules\\kz.txt --url http://localhost/base/odata/standard.odata --profile kz   (ODATA_USER/ODATA_PASSWORD)

Что попадает в политику:
- поля из правил: идентификаторы, счета, имена, наименования, даты рождения - токенами (token:<класс>);
- числа, даты, булевы и ссылки (поля *_Key) - как есть (pass): по ним считают суммы и связи;
- ВСЕ остальные строки (комментарии, адреса, телефоны, свободный текст) НЕ попадают - в них бывают персональные данные.
Разрешить конкретную строку явно: --pass Catalog_Номенклатура.Description. Результат - черновик: прочитайте его перед запуском шлюза.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from typing import Iterable

KIND = {"Справочник": "Catalog", "Документ": "Document"}
CLASS = {"идентификатор": "iin", "снилс": "snils", "счет": "iban", "заменить_счет": "iban", "фио": "name", "фамилия": "name", "имя": "name",
         "отчество": "name", "наименование": "name", "наименование_полное": "name", "дата рождения": "birth"}
CLASS_RU = dict(CLASS, идентификатор="inn")
SAFE_TYPES = ("Edm.Boolean", "Edm.DateTime", "Edm.DateTimeOffset", "Edm.Decimal", "Edm.Double", "Edm.Single", "Edm.Int16", "Edm.Int32", "Edm.Int64", "Edm.Guid")
ALWAYS = ("Ref_Key", "DeletionMark", "IsFolder", "Parent_Key", "Number", "Date", "Posted", "LineNumber")
ATTR = {"Наименование": "Description", "Код": "Code", "Номер": "Number", "Дата": "Date"}


def parse_rules(lines: Iterable[str], profile: str) -> "dict[str, dict[str, str]]":
    """{набор OData: {поле: класс токена}} из строк правил Объект|Реквизит|Класс; табличные части и прочее пропускаются."""
    classes = CLASS_RU if profile == "ru" else CLASS
    out: dict[str, dict[str, str]] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            continue
        obj, attr, cls = parts
        kind, _, name = obj.partition(".")
        if kind not in KIND or "." in name or cls.lower() not in classes:
            continue
        out.setdefault("%s_%s" % (KIND[kind], name), {})[ATTR.get(attr, attr)] = classes[cls.lower()]
    return out


def parse_metadata(xml_text: str) -> "dict[str, dict[str, str]]":
    """{набор: {поле: тип EDM}} из документа $metadata."""
    root = ET.fromstring(xml_text)
    result: dict[str, dict[str, str]] = {}
    for el in root.iter():
        if el.tag.split("}")[-1] == "EntityType" and el.get("Name"):
            result[el.get("Name")] = {p.get("Name"): p.get("Type", "") for p in el if p.tag.split("}")[-1] == "Property"}
    return result


def build_policy(rules: "dict[str, dict[str, str]]", metadata: "dict[str, dict[str, str]]", profile: str,
                 extra_pass: Iterable[str] = (), entities: Iterable[str] = (), max_top: int = 200) -> "tuple[dict, list[str]]":
    """Политика и список замечаний. Набор попадает в политику, если он есть в $metadata и (в правилах или в --entities)."""
    wanted = set(entities) | set(rules)
    allow = {}
    for item in extra_pass:
        name, _, field = item.partition(".")
        allow.setdefault(name, set()).add(field)
    entities_out: dict[str, dict] = {}
    notes: list[str] = []
    for name in sorted(wanted):
        props = metadata.get(name)
        if props is None:
            if name in rules:
                notes.append("Набор %s из правил не найден в $metadata (не опубликован в OData?) - пропущен" % name)
            continue
        fields: dict[str, str] = {}
        for field, edm in props.items():
            if field in rules.get(name, {}):
                fields[field] = "token:" + rules[name][field]
            elif field in allow.get(name, ()):
                fields[field] = "pass"
            elif field in ALWAYS or field.endswith("_Key") or edm in SAFE_TYPES:
                fields[field] = "pass"
        skipped = [f for f, t in props.items() if f not in fields and t == "Edm.String"]
        if skipped:
            notes.append("%s: исключены строки (проверьте, нет ли среди них нужных): %s" % (name, ", ".join(skipped[:12]) + (" ..." if len(skipped) > 12 else "")))
        entities_out[name] = {"fields": fields}
    return ({"profile": profile, "max_top": max_top,
             "upstream": {"base_url": "http://localhost/<публикация>/odata/standard.odata", "user_env": "ODATA_USER", "password_env": "ODATA_PASSWORD"},
             "entities": entities_out}, notes)


def main() -> int:
    ap = argparse.ArgumentParser(description="Черновик политики шлюза из правил обезличивания и $metadata")
    ap.add_argument("--rules", required=True)
    ap.add_argument("--profile", choices=("kz", "ru"), default="kz")
    ap.add_argument("--metadata", help="файл $metadata")
    ap.add_argument("--url", help="адрес OData; $metadata читается с ODATA_USER/ODATA_PASSWORD")
    ap.add_argument("--entities", default="", help="доп. наборы без правил обезличивания, через запятую")
    ap.add_argument("--pass", dest="extra", action="append", default=[], help="Набор.Поле: разрешить строковое поле как есть")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    if bool(a.metadata) == bool(a.url):
        raise SystemExit("Укажите ровно одно из --metadata и --url")
    if a.metadata:
        xml_text = open(a.metadata, encoding="utf-8-sig").read()
    else:
        req = urllib.request.Request(a.url.rstrip("/") + "/$metadata")
        user, pwd = os.environ.get("ODATA_USER", ""), os.environ.get("ODATA_PASSWORD", "")
        if user:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii"))
        with urllib.request.urlopen(req, timeout=300) as r:
            xml_text = r.read().decode("utf-8-sig")
    rules = parse_rules(open(a.rules, encoding="utf-8-sig").read().splitlines(), a.profile)
    policy, notes = build_policy(rules, parse_metadata(xml_text), a.profile, a.extra, [e for e in a.entities.split(",") if e])
    if a.url:
        policy["upstream"]["base_url"] = a.url
    text = json.dumps(policy, ensure_ascii=False, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")
    for n in notes:
        print("! " + n, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
