import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from canary.battery import ENTITY, IIN_FIELD, attacks, fake_upstream, find_leaks, run_battery
from canary.canaries import make_canaries
from canary.selftest import POLICY, _call, build
from gateway.gate import Gate, Policy
from gateway.server import make_server

E = urllib.parse.quote(ENTITY)


class GateBehaviourTests(unittest.TestCase):
    def setUp(self):
        self.data, self.gate, self.seen = build()

    def get(self, target, method="GET"):
        return self.gate.handle(method, target)

    def test_list_is_tokenized_and_allowlisted(self):
        status, body = self.get(f"/{E}")
        self.assertEqual(status, 200)
        row = body["value"][0]
        self.assertEqual(set(row), {"Ref_Key", "Code", "Description", IIN_FIELD, "Number"})
        self.assertRegex(row[IIN_FIELD], r"^\[\[iin:[A-Z2-7]{10}\]\]$")
        self.assertRegex(row["Description"], r"^\[\[name:[A-Z2-7]{10}\]\]$")
        self.assertNotIn(self.data["rows"][0][IIN_FIELD], row["Number"])  # страж в поле pass
        self.assertEqual(row["Ref_Key"], self.data["rows"][0]["Ref_Key"])

    def test_same_value_same_token_other_secret_other_token(self):
        a = self.get(f"/{E}")[1]["value"][0][IIN_FIELD]
        b = self.get(f"/{E}")[1]["value"][0][IIN_FIELD]
        other = Gate(Policy(POLICY), b"another-secret-0123456789ab", fake_upstream(self.data["rows"], []))
        c = other.handle("GET", f"/{E}")[1]["value"][0][IIN_FIELD]
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_lookup_by_token_reaches_upstream_with_real_value(self):
        token = self.get(f"/{E}")[1]["value"][0][IIN_FIELD]
        q = urllib.parse.quote(f"{IIN_FIELD} eq '{token}'")
        status, body = self.get(f"/{E}?$filter={q}")
        self.assertEqual((status, len(body["value"])), (200, 1))
        self.assertTrue(any(self.data["rows"][0][IIN_FIELD] in urllib.parse.unquote(s) for s in self.seen))

    def test_make_policy_is_safe_by_default(self):
        from gateway import make_policy
        rules = make_policy.parse_rules(["# c", "Справочник.Контрагенты|ИдентификационныйКодЛичности|идентификатор",
                                         "Справочник.Контрагенты|Наименование|наименование", "Справочник.Контрагенты|Комментарий|текст",
                                         "Справочник.Контрагенты.Контакты|Телефон|контакт", "Документ.Реализация|Контрагент|зерно"], "kz")
        self.assertEqual(rules, {"Catalog_Контрагенты": {"ИдентификационныйКодЛичности": "iin", "Description": "name"}})
        xml = ('<Edmx xmlns="x"><Schema xmlns="y"><EntityType Name="Catalog_Контрагенты"><Property Name="Ref_Key" Type="Edm.Guid"/>'
               '<Property Name="Description" Type="Edm.String"/><Property Name="ИдентификационныйКодЛичности" Type="Edm.String"/>'
               '<Property Name="Комментарий" Type="Edm.String"/><Property Name="Телефон" Type="Edm.String"/><Property Name="ДатаСоздания" Type="Edm.DateTime"/>'
               '</EntityType><EntityType Name="Catalog_Номенклатура"><Property Name="Ref_Key" Type="Edm.Guid"/><Property Name="Description" Type="Edm.String"/>'
               '</EntityType></Schema></Edmx>')
        policy, notes = make_policy.build_policy(rules, make_policy.parse_metadata(xml), "kz", ["Catalog_Номенклатура.Description"], ["Catalog_Номенклатура"])
        fields = policy["entities"]["Catalog_Контрагенты"]["fields"]
        self.assertEqual(fields, {"Ref_Key": "pass", "Description": "token:name", "ИдентификационныйКодЛичности": "token:iin", "ДатаСоздания": "pass"})
        self.assertNotIn("Комментарий", fields)  # свободный текст по умолчанию исключен
        self.assertEqual(policy["entities"]["Catalog_Номенклатура"]["fields"]["Description"], "pass")  # только по явному --pass
        self.assertTrue(any("Комментарий" in n for n in notes))
        Policy(policy)  # итог проходит проверку политики шлюза

    def test_catalog_lists_allowed_entities_and_field_modes_without_values(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        fields = body["entities"][ENTITY]["fields"]
        self.assertEqual(fields[IIN_FIELD], "token")
        self.assertEqual(fields["Ref_Key"], "pass")
        self.assertNotIn(self.data["rows"][0][IIN_FIELD], json.dumps(body, ensure_ascii=False))

    def test_mcp_tools_go_only_through_gateway(self):
        from gateway import mcp_server

        def fetch(target):
            status, body = self.gate.handle("GET", target)
            return status, body

        init = mcp_server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}, fetch)
        self.assertEqual(init["result"]["serverInfo"]["name"], "1c-ai-data-guard")
        self.assertIsNone(mcp_server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}, fetch))
        names = [t["name"] for t in mcp_server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, fetch)["result"]["tools"]]
        self.assertEqual(names, ["describe_data", "query_data"])

        def call(name, args):
            reply = mcp_server.handle_message({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": name, "arguments": args}}, fetch)
            return reply["result"]

        described = call("describe_data", {})
        self.assertFalse(described["isError"])
        ok = call("query_data", {"entity": ENTITY, "top": 2, "skip": 0})
        self.assertFalse(ok["isError"])
        self.assertRegex(ok["content"][0]["text"], r"\[\[iin:[A-Z2-7]{10}\]\]")
        self.assertNotIn(self.data["rows"][0][IIN_FIELD], ok["content"][0]["text"])
        real = call("query_data", {"entity": ENTITY, "filter": "%s eq '%s'" % (IIN_FIELD, self.data["rows"][0][IIN_FIELD])})
        self.assertTrue(real["isError"])  # реальный ИИН искать нельзя и через MCP
        self.assertIn("Ref_Key", mcp_server.build_query_path({"entity": "X", "skip": 100}))  # страницы - с сортировкой

    def test_reveal_restores_values_only_with_gateway_secret(self):
        from gateway.reveal import reveal
        row = self.get(f"/{E}")[1]["value"][0]
        answer = "Крупнейший покупатель %s, ИИН %s, и [[name:AAAAAAAAAA]]" % (row["Description"], row[IIN_FIELD])
        upstream = fake_upstream(self.data["rows"], [])
        text, missing = reveal(answer, Policy(POLICY), self.gate.tokenizer._secret, upstream)
        self.assertIn(self.data["rows"][0]["Description"], text)
        self.assertIn(self.data["rows"][0][IIN_FIELD], text)
        self.assertEqual(missing, {"[[name:AAAAAAAAAA]]"})
        other, _ = reveal(answer, Policy(POLICY), b"another-secret-0123456789ab", upstream)
        self.assertEqual(other, answer)

    def test_status_codes_of_attacks(self):
        expected = {
            "поле вне политики": 400, "телефон вне политики": 400, "фильтр по реальному ИИН": 400,
            "фильтр по реальному ИИН в двойных кавычках": 400, "фильтр по имени без токена": 400, "подстрока в имени": 400,
            "неизвестный токен": 400, "фильтр или-условием": 400, "ИИН внутри поля pass": 400,
            "сортировка по защищаемому полю": 400, "раскрытие связей": 400, "метаданные": 404, "пакетный запрос": 404,
            "чужой набор": 404, "выход из пути": 400, "двойной слеш": 404, "запись": 405, "удаление": 405,
            "формат xml": 400, "лишний параметр": 400, "эхо ошибки источника": 502,
        }
        token = self.get(f"/{E}")[1]["value"][0][IIN_FIELD]
        for label, method, target in attacks(self.data["rows"], token):
            status, _ = self.get(target, method)
            if label in expected:
                self.assertEqual(status, expected[label], label)
            else:
                self.assertEqual(status, 200, label)

    def test_top_is_clipped_to_policy(self):
        self.get(f"/{E}?$top=1000000000")
        self.assertTrue(any("%24top=50" in s or "$top=50" in s for s in self.seen))

    def test_upstream_error_text_is_not_forwarded(self):
        q = urllib.parse.quote("Number eq 'boom ТайноеИмя'")
        status, body = self.get(f"/{E}?$filter={q}")
        self.assertEqual(status, 502)
        self.assertNotIn("ТайноеИмя", json.dumps(body, ensure_ascii=False))

    def test_log_has_no_values(self):
        run_battery(lambda m, t: _call(self.gate, m, t), self.data["rows"])
        text = json.dumps(self.gate.log, ensure_ascii=False)
        self.assertEqual(find_leaks([], self.data["secrets"], extra=(text,)), [])

    def test_bad_policy_mode_rejected(self):
        with self.assertRaises(ValueError):
            Policy({"entities": {"X": {"fields": {"A": "raw"}}}})
        with self.assertRaises(ValueError):
            Policy({"profile": "xx"})


class CanaryDetectorTests(unittest.TestCase):
    def run_with(self, policy, profile="kz"):
        data = make_canaries(profile)
        gate = Gate(Policy(policy), b"canary-selftest-secret-0123456789", fake_upstream(data["rows"], []))
        results = run_battery(lambda m, t: _call(gate, m, t), data["rows"])
        return find_leaks(results, data["secrets"])

    def test_secure_policy_has_no_leaks_kz_and_ru(self):
        self.assertEqual(self.run_with(POLICY), [])
        ru = json.loads(json.dumps(POLICY))
        ru["profile"] = "ru"
        self.assertEqual(self.run_with(ru, "ru"), [])

    def test_weak_policy_is_detected(self):
        weak = json.loads(json.dumps(POLICY))
        weak["entities"][ENTITY]["fields"]["Description"] = "pass"  # имена без шаблона страж не ловит
        leaks = self.run_with(weak)
        self.assertTrue(any(cls == "name" for _, cls, _ in leaks))

    def test_policy_exposing_comment_is_detected(self):
        weak = json.loads(json.dumps(POLICY))
        weak["entities"][ENTITY]["fields"]["ПаспортныеДанные"] = "pass"
        self.assertTrue(self.run_with(weak))


class HttpServerTests(unittest.TestCase):
    def test_http_gateway_end_to_end(self):
        data = make_canaries("kz")
        gate = Gate(Policy(POLICY), b"http-secret-0123456789abcdef", fake_upstream(data["rows"], []))
        srv = make_server(gate, "127.0.0.1", 0, client_token="t0ken")
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            base = f"http://127.0.0.1:{port}"

            def call(method, target, token="t0ken"):
                req = urllib.request.Request(base + target, method=method)
                if token:
                    req.add_header("X-Gate-Token", token)
                try:
                    with urllib.request.urlopen(req, timeout=10) as r:
                        return r.status, r.read().decode("utf-8")
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode("utf-8")

            self.assertEqual(call("GET", f"/{E}", token="")[0], 403)
            self.assertEqual(call("GET", f"/{E}", token="bad")[0], 403)
            self.assertEqual(call("GET", f"/{E}")[0], 200)
            self.assertEqual(call("POST", f"/{E}")[0], 405)
            results = run_battery(call, data["rows"])
            self.assertEqual(find_leaks(results, data["secrets"]), [])
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
