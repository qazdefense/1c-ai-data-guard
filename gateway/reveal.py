"""Расшифровка ответа ИИ для человека: токены [[класс:XXXXXXXXXX]] заменяются настоящими значениями из 1С.

python -m gateway.reveal --policy politika.json --in otvet.txt [--out rasshifrovka.txt]

Запускается там же, где шлюз, с теми же секретом и учетными данными 1С (переменные окружения): токен необратим без секрета,
поэтому значения находятся перебором полей политики с этим классом. ИИ-сессии этот инструмент недоступен.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse

from dataguard.scanner import PROFILES, Tokenizer

from .gate import Fetch, Policy, http_fetcher

ANY_TOKEN_RE = re.compile(r"\[\[([a-z_]{2,16}):[A-Z2-7]{10}\]\]")


def reveal(text: str, policy: Policy, secret: bytes, fetch: Fetch, page: int = 1000) -> "tuple[str, set[str]]":
    """Текст с настоящими значениями вместо токенов и множество токенов, которые не нашлись в полях политики."""
    need = {m.group(0) for m in ANY_TOKEN_RE.finditer(text)}
    classes = {ANY_TOKEN_RE.match(t).group(1) for t in need}
    tokenizer = Tokenizer(secret, PROFILES[policy.profile]())
    found: dict[str, str] = {}
    for entity, fields in policy.entities.items():
        targets = {f: m.split(":", 1)[1] for f, m in fields.items() if m.startswith("token:") and m.split(":", 1)[1] in classes}
        skip = 0
        while targets and need - found.keys():
            # без сортировки 1С не гарантирует один порядок между страницами
            query = urllib.parse.urlencode({"$select": ",".join(targets), "$orderby": "Ref_Key", "$top": str(page), "$skip": str(skip),
                                            "$format": "json"}, quote_via=urllib.parse.quote)
            status, raw = fetch("/" + urllib.parse.quote(entity, safe="") + "?" + query)
            if status != 200:
                raise RuntimeError("Источник ответил %d на чтение %s, расшифровка неполная - повторите" % (status, entity))
            rows = json.loads(raw.decode("utf-8-sig")).get("value") or []
            for row in rows:
                for field, cls in targets.items():
                    value = row.get(field)
                    if value not in (None, ""):
                        token = tokenizer.token(cls, str(value))
                        if token in need:
                            found[token] = str(value)
            if len(rows) < page:
                break
            skip += page
    return ANY_TOKEN_RE.sub(lambda m: found.get(m.group(0), m.group(0)), text), need - found.keys()


def main() -> int:
    ap = argparse.ArgumentParser(description="Расшифровка токенов шлюза в ответе ИИ (только для человека)")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--in", dest="src", default="-")
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    policy = Policy.load(a.policy)
    secret = os.environ.get("DATAGUARD_SECRET", "").encode("utf-8")
    if len(secret) < 16:
        raise SystemExit("Задайте DATAGUARD_SECRET (тот же, что у шлюза)")
    up = policy.upstream
    fetch = http_fetcher(up["base_url"], os.environ.get(up.get("user_env", "ODATA_USER"), ""),
                         os.environ.get(up.get("password_env", "ODATA_PASSWORD"), ""), timeout=300)
    text = sys.stdin.read() if a.src == "-" else open(a.src, encoding="utf-8-sig").read()
    result, missing = reveal(text, policy, secret, fetch)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(result)
    else:
        sys.stdout.write(result)
    if missing:
        print("\nНе найдено в полях политики: %d (токены стража из полей pass и чужого секрета не расшифровываются)" % len(missing),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
