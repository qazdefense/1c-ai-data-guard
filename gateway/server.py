"""HTTP-оболочка шлюза: python -m gateway.server --policy politika.json --port 8790. Секреты - только из переменных окружения."""
from __future__ import annotations

import argparse
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .gate import Gate, Policy, http_fetcher


def make_server(gate: Gate, host: str = "127.0.0.1", port: int = 8790, client_token: str = "") -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self, head_only: bool) -> None:
            if client_token and not hmac.compare_digest(self.headers.get("X-Gate-Token", ""), client_token):
                status, body = 403, {"error": "Нет доступа"}
            else:
                status, body = gate.handle("HEAD" if head_only else "GET", self.path)
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if not head_only:
                self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            self._serve(False)

        def do_HEAD(self) -> None:  # noqa: N802
            self._serve(True)

        def _deny(self) -> None:
            data = json.dumps({"error": "Разрешено только чтение"}, ensure_ascii=False).encode("utf-8")
            self.send_response(405)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _deny  # noqa: N815

        def log_message(self, fmt: str, *args: object) -> None:  # значения в журнал не пишем
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    srv.daemon_threads = True
    return srv


def main() -> int:
    ap = argparse.ArgumentParser(description="Шлюз к OData 1С с подменой персональных данных")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8790)
    a = ap.parse_args()
    policy = Policy.load(a.policy)
    secret = os.environ.get("DATAGUARD_SECRET", "").encode("utf-8")
    if len(secret) < 16:
        raise SystemExit("Задайте DATAGUARD_SECRET (не короче 16 знаков)")
    up = policy.upstream
    fetch = http_fetcher(up["base_url"], os.environ.get(up.get("user_env", "ODATA_USER"), ""),
                         os.environ.get(up.get("password_env", "ODATA_PASSWORD"), ""))
    gate = Gate(policy, secret, fetch)
    srv = make_server(gate, a.host, a.port, os.environ.get("DATAGUARD_CLIENT_TOKEN", ""))
    print("Шлюз слушает http://%s:%d" % (a.host, a.port))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
