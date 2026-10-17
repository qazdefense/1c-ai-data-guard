"""Шлюз к OData 1С: только чтение, белый список сущностей и полей, подмена значений токенами, без фильтров по реальным значениям."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from dataguard.scanner import PROFILES, Tokenizer, scan

TOKEN_RE = re.compile(r"^\[\[([a-z_]{2,16}):([A-Z2-7]{10})\]\]$")
PATH_RE = re.compile(r"^/(?P<set>[^/()$]+)(?:\(guid'(?P<key>[0-9a-fA-F-]{36})'\))?(?P<count>/\$count)?$")
CLAUSE_RE = re.compile(r"^(?P<f>[^\W\d]\w*)\s+(?P<op>eq|ne|gt|ge|lt|le)\s+(?P<v>.+)$", re.U)
ALLOWED_PARAMS = {"$select", "$filter", "$top", "$skip", "$orderby", "$count", "$format"}
MODE_RE = re.compile(r"^(pass|token:[a-z_]{2,16})$")


class GateError(Exception):
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class Policy:
    """entities: {имя набора: {поле: "pass" | "token:<класс>"}}; поля, которых нет в политике, наружу не выходят."""

    def __init__(self, data: dict[str, Any]):
        self.profile = data.get("profile", "kz")
        if self.profile not in PROFILES:
            raise ValueError("Неизвестный профиль: %s" % self.profile)
        self.max_top = int(data.get("max_top", 200))
        self.entities: dict[str, dict[str, str]] = {}
        for name, spec in (data.get("entities") or {}).items():
            fields = spec.get("fields") or {}
            for field, mode in fields.items():
                if not MODE_RE.match(mode):
                    raise ValueError("Режим поля %s.%s: %r (нужно pass или token:<класс>)" % (name, field, mode))
            self.entities[name] = dict(fields)
        self.upstream = data.get("upstream") or {}

    @classmethod
    def load(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8-sig") as fh:
            return cls(json.load(fh))


Fetch = Callable[[str], "tuple[int, bytes]"]


class Gate:
    def __init__(self, policy: Policy, secret: bytes, fetch: Fetch):
        self.policy = policy
        self.profile = PROFILES[policy.profile]()
        self.tokenizer = Tokenizer(secret, self.profile)
        self.fetch = fetch
        self.log: list[dict[str, Any]] = []

    # ---- публичный вход ----
    def handle(self, method: str, target: str) -> "tuple[int, dict[str, Any]]":
        entry: dict[str, Any] = {"method": method, "status": 0}
        try:
            if method not in ("GET", "HEAD"):
                raise GateError(405, "Разрешено только чтение")
            status, body = 200, self._get(target, entry)
        except GateError as exc:
            status, body = exc.status, {"error": exc.reason}
            entry["rejected"] = exc.reason
        entry["status"] = status
        self.log.append(entry)
        return status, body

    # ---- разбор запроса ----
    def _get(self, target: str, entry: dict[str, Any]) -> dict[str, Any]:
        parts = urllib.parse.urlsplit(target)
        path = urllib.parse.unquote(parts.path)
        if ".." in path or "//" in path or "\\" in path:
            raise GateError(400, "Недопустимый путь")
        m = PATH_RE.match(path)
        if not m:
            raise GateError(404, "Запрос не разрешен политикой")
        name = m.group("set")
        fields = self.policy.entities.get(name)
        if fields is None:
            raise GateError(404, "Набор данных не разрешен политикой")
        entry["entity"] = name
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        params: dict[str, str] = {}
        for key, value in pairs:
            if key not in ALLOWED_PARAMS or key in params:
                raise GateError(400, "Параметр запроса не разрешен: %s" % key)
            params[key] = value
        if params.get("$format", "json") != "json":
            raise GateError(400, "Только формат json")

        query: dict[str, str] = {"$format": "json"}
        select = [s.strip() for s in params["$select"].split(",")] if params.get("$select") else list(fields)
        for s in select:
            if s not in fields:
                raise GateError(400, "Поле не разрешено политикой: %s" % s)
        query["$select"] = ",".join(select)
        if params.get("$filter"):
            query["$filter"] = self._filter(params["$filter"], fields)
        if params.get("$orderby"):
            query["$orderby"] = self._orderby(params["$orderby"], fields)
        query["$top"] = str(self._number(params.get("$top"), self.policy.max_top, clip=True))
        if params.get("$skip"):
            query["$skip"] = str(self._number(params["$skip"], 10**9))
        if params.get("$count"):
            query["$count"] = "true" if params["$count"] == "true" else "false"

        url = "/" + urllib.parse.quote(name, safe="")
        if m.group("key"):
            url += "(guid'%s')" % m.group("key")
        if m.group("count"):
            url += "/$count"
            query = {k: v for k, v in query.items() if k in ("$filter",)}
        status, raw = self.fetch(url + "?" + urllib.parse.urlencode(query, quote_via=urllib.parse.quote))
        if status != 200:
            raise GateError(502, "Ошибка источника данных (%d)" % status)
        if m.group("count"):
            try:
                return {"count": int(raw.decode("ascii").strip().lstrip("﻿"))}
            except ValueError:
                raise GateError(502, "Источник вернул не число")
        try:
            data = json.loads(raw.decode("utf-8-sig"))
        except ValueError:
            raise GateError(502, "Источник вернул не JSON")
        return self._shape(data, fields, entry)

    @staticmethod
    def _number(value: Optional[str], limit: int, clip: bool = False) -> int:
        if value is None or value == "":
            return limit if clip else 0
        if not value.isdigit():
            raise GateError(400, "Нужно целое число")
        return min(int(value), limit) if clip else int(value)

    def _orderby(self, text: str, fields: dict[str, str]) -> str:
        out = []
        for item in text.split(","):
            bits = item.split()
            if not bits or len(bits) > 2 or (len(bits) == 2 and bits[1] not in ("asc", "desc")):
                raise GateError(400, "Недопустимая сортировка")
            # порядок по токенизируемому полю раскрывает порядок реальных значений
            if fields.get(bits[0]) != "pass":
                raise GateError(400, "Сортировка по этому полю запрещена")
            out.append(" ".join(bits))
        return ",".join(out)

    def _filter(self, text: str, fields: dict[str, str]) -> str:
        """Только условия через and вида Поле op значение. Реальные значения защищаемых полей искать нельзя: только токен из ответа."""
        clauses = re.split(r"\s+and\s+", text.strip(), flags=re.I)
        out = []
        for clause in clauses:
            m = CLAUSE_RE.match(clause.strip())
            if not m or m.group("f") not in fields:
                raise GateError(400, "Условие фильтра не разрешено")
            field, op, literal = m.group("f"), m.group("op"), m.group("v").strip()
            mode = fields[field]
            if mode.startswith("token:"):
                s = re.match(r"^'(.*)'$", literal)
                tm = TOKEN_RE.match(s.group(1)) if s else None
                if not tm or op not in ("eq", "ne"):
                    raise GateError(400, "Это поле можно сравнивать только на равенство с токеном из ответа шлюза")
                real = self.tokenizer.resolve(s.group(1))
                if real is None:
                    raise GateError(400, "Неизвестный токен")
                literal = "'%s'" % real.replace("'", "''")
            else:
                inner = re.match(r"^'(.*)'$", literal)
                if inner and (scan(inner.group(1), self.profile) or self.tokenizer.protect(inner.group(1)) != inner.group(1)):
                    raise GateError(400, "Значение похоже на персональные данные")
            out.append("%s %s %s" % (field, op, literal))
        return " and ".join(out)

    # ---- ответ ----
    def _shape(self, data: Any, fields: dict[str, str], entry: dict[str, Any]) -> dict[str, Any]:
        rows = data.get("value") if isinstance(data, dict) and isinstance(data.get("value"), list) else [data]
        shaped = [self._row(r, fields) for r in rows if isinstance(r, dict)]
        entry["rows"] = len(shaped)
        result: dict[str, Any] = {"value": shaped}
        if isinstance(data, dict) and isinstance(data.get("odata.count", data.get("@odata.count")), (int, str)):
            result["count"] = data.get("odata.count", data.get("@odata.count"))
        return result

    def _row(self, row: dict[str, Any], fields: dict[str, str]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for field, mode in fields.items():
            if field not in row:
                continue
            value = row[field]
            if isinstance(value, (dict, list)):
                out[field] = None
            elif mode == "pass":
                out[field] = self.tokenizer.protect(value) if isinstance(value, str) else value
            else:
                out[field] = self.tokenizer.token(mode.split(":", 1)[1], str(value)) if value not in (None, "") else value
        return out


def http_fetcher(base_url: str, user: str = "", password: str = "", timeout: float = 30.0) -> Fetch:
    """Запрос к настоящему OData; адрес и учетные данные знает только шлюз, без перенаправлений."""
    import base64

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # type: ignore[override]
            return None

    opener = urllib.request.build_opener(_NoRedirect)

    def fetch(path_and_query: str) -> "tuple[int, bytes]":
        req = urllib.request.Request(base_url.rstrip("/") + path_and_query)
        if user:
            req.add_header("Authorization", "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii"))
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, b""
        except (urllib.error.URLError, OSError):
            return 599, b""

    return fetch
