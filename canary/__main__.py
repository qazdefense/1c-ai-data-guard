"""Проверка живого шлюза на утечку: python -m canary --gateway http://127.0.0.1:8790 --canaries canaries.json [--token T].

canaries.json - {"rows": [...], "secrets": [[класс, значение], ...]}: те же значения должны лежать в проверяемой тестовой базе.
Для самопроверки без 1С: python -m canary --selftest.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from .battery import find_leaks, run_battery


def http_call(base: str, token: str = ""):
    def call(method: str, target: str):
        req = urllib.request.Request(base.rstrip("/") + target, method=method)
        if token:
            req.add_header("X-Gate-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
    return call


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway")
    ap.add_argument("--canaries")
    ap.add_argument("--token", default="")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        from .selftest import selftest
        return selftest()
    if not (a.gateway and a.canaries):
        ap.error("нужны --gateway и --canaries (или --selftest)")
    data = json.load(open(a.canaries, encoding="utf-8"))
    results = run_battery(http_call(a.gateway, a.token), data["rows"])
    leaks = find_leaks(results, [tuple(x) for x in data["secrets"]])
    for label, status, _ in results:
        print("%-45s %s" % (label, status))
    print("УТЕЧЕК: %d" % len(leaks))
    for label, cls, value in leaks:
        print("  утекло (%s) в запросе «%s»: %s" % (cls, label, value[:4] + "..."))
    return 1 if leaks else 0


if __name__ == "__main__":
    sys.exit(main())
