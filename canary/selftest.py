"""Самопроверка без 1С: шлюз над поддельным источником с канарейками, полный набор атак."""
from __future__ import annotations

import json

from gateway.gate import Gate, Policy

from .battery import ENTITY, IIN_FIELD, fake_upstream, find_leaks, run_battery
from .canaries import make_canaries

POLICY = {
    "profile": "kz", "max_top": 50,
    "entities": {ENTITY: {"fields": {"Ref_Key": "pass", "Code": "pass", "Description": "token:name", IIN_FIELD: "token:iin", "Number": "pass"}}},
}


def build(profile: str = "kz"):
    data = make_canaries(profile)
    seen: list[str] = []
    gate = Gate(Policy(POLICY), b"canary-selftest-secret-0123456789", fake_upstream(data["rows"], seen))
    return data, gate, seen


def selftest() -> int:
    data, gate, _ = build()
    results = run_battery(lambda m, t: _call(gate, m, t), data["rows"])
    leaks = find_leaks(results, data["secrets"], extra=(json.dumps(gate.log, ensure_ascii=False),))
    print("запросов: %d, утечек: %d" % (len(results), len(leaks)))
    return 1 if leaks else 0


def _call(gate: Gate, method: str, target: str):
    status, body = gate.handle(method, target)
    return status, json.dumps(body, ensure_ascii=False)
