"""MCP-сервер (stdio) над шлюзом: ИИ-клиент (Claude Code, Claude Desktop, любой MCP-клиент) получает два инструмента и ходит
только в шлюз, а не в 1С напрямую.

  claude mcp add 1c-guard --env DATAGUARD_URL=http://127.0.0.1:8790 -- py -m gateway.mcp_server

Переменные окружения: DATAGUARD_URL (по умолчанию http://127.0.0.1:8790), DATAGUARD_CLIENT_TOKEN (заголовок X-Gate-Token).
Секрета токенов и учетных данных 1С у этого процесса нет - они только у шлюза. Стандартная библиотека, без зависимостей.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

PROTOCOL_VERSION = "2024-11-05"

TOOLS = [
    {
        "name": "describe_data",
        "description": "Что можно читать: наборы данных 1С и их поля. Поля 'token' приходят токенами вида [[iin:XXXXXXXXXX]] (настоящих значений "
                       "модель не видит), по ним можно искать только на равенство токену из ответа. Вызови первым.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "query_data",
        "description": "Прочитать набор данных 1С через шлюз (только чтение). Большие наборы читай страницами; при skip сортировка по Ref_Key "
                       "добавляется сама (без нее 1С отдает строки страниц в разном порядке).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entity": {"type": "string", "description": "Имя набора из describe_data, например Catalog_Контрагенты"},
                "select": {"type": "array", "items": {"type": "string"}, "description": "Поля; по умолчанию все разрешенные"},
                "filter": {"type": "string", "description": "OData $filter: условия через and; по полю-токену только eq/ne с токеном из ответа"},
                "orderby": {"type": "string", "description": "Только по полям без токена, например Date desc"},
                "top": {"type": "integer"},
                "skip": {"type": "integer"},
                "count": {"type": "boolean", "description": "Только число строк по filter"},
            },
            "required": ["entity"],
        },
    },
]

Fetch = Callable[[str], "tuple[int, Any]"]


def http_gateway(base_url: str, client_token: str = "", timeout: float = 300.0) -> Fetch:
    def fetch(path_and_query: str) -> "tuple[int, Any]":
        req = urllib.request.Request(base_url.rstrip("/") + path_and_query)
        if client_token:
            req.add_header("X-Gate-Token", client_token)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read().decode("utf-8") or "{}")
            except ValueError:
                return e.code, {"error": "Ошибка шлюза"}
        except (urllib.error.URLError, OSError):
            return 599, {"error": "Шлюз недоступен"}
    return fetch


def build_query_path(args: dict[str, Any]) -> str:
    entity = str(args.get("entity") or "")
    if not entity:
        raise ValueError("Не указан entity")
    count = bool(args.get("count"))
    params: dict[str, str] = {}
    if args.get("filter"):
        params["$filter"] = str(args["filter"])
    if not count:
        if args.get("select"):
            params["$select"] = ",".join(str(s) for s in args["select"])
        if args.get("orderby"):
            params["$orderby"] = str(args["orderby"])
        elif args.get("skip"):
            params["$orderby"] = "Ref_Key"
        if args.get("top") is not None:
            params["$top"] = str(int(args["top"]))
        if args.get("skip"):
            params["$skip"] = str(int(args["skip"]))
    path = "/" + urllib.parse.quote(entity, safe="") + ("/$count" if count else "")
    return path + ("?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote) if params else "")


def call_tool(name: str, args: dict[str, Any], fetch: Fetch) -> dict[str, Any]:
    try:
        if name == "describe_data":
            status, body = fetch("/")
        elif name == "query_data":
            status, body = fetch(build_query_path(args))
        else:
            return {"isError": True, "content": [{"type": "text", "text": "Неизвестный инструмент: %s" % name}]}
    except (ValueError, TypeError) as exc:
        return {"isError": True, "content": [{"type": "text", "text": "Неверные параметры: %s" % exc}]}
    return {"isError": status != 200, "content": [{"type": "text", "text": json.dumps(body, ensure_ascii=False)}]}


def handle_message(msg: dict[str, Any], fetch: Fetch) -> Optional[dict[str, Any]]:
    """Ответ на одно сообщение JSON-RPC; для уведомлений (без id) - None."""
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None
    if method == "initialize":
        result: dict[str, Any] = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                                  "serverInfo": {"name": "1c-ai-data-guard", "version": "1.0"}}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params") or {}
        result = call_tool(str(params.get("name") or ""), params.get("arguments") or {}, fetch)
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Метод не поддерживается: %s" % method}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def main() -> int:
    fetch = http_gateway(os.environ.get("DATAGUARD_URL", "http://127.0.0.1:8790"), os.environ.get("DATAGUARD_CLIENT_TOKEN", ""))
    stdin = open(sys.stdin.fileno(), encoding="utf-8", errors="replace", closefd=False)
    stdout = open(sys.stdout.fileno(), "w", encoding="utf-8", newline="\n", closefd=False)
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            reply = handle_message(json.loads(line), fetch)
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Некорректный JSON"}}
        if reply is not None:
            stdout.write(json.dumps(reply, ensure_ascii=False) + "\n")
            stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
