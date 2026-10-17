import datetime
import random
import unittest

from dataguard import checksums as ck
from dataguard.scanner import Tokenizer, leak_check, profile_kz, profile_ru, scan

SECRET = b"unit-test-secret-0123456789"


class ScanTests(unittest.TestCase):
    def setUp(self):
        rng = random.Random(10)
        self.iin = ck.make_kz_iin(datetime.date(1990, 4, 12), False, rng)
        self.bin = ck.make_kz_bin("1807", rng)
        self.iban = ck.make_kz_iban(rng)

    def test_kz_finds_valid_identifiers(self):
        text = f"ИИН {self.iin}, БИН {self.bin}, счет {self.iban}, тел +7 701 234 56 78, a.b@mail.kz"
        classes = sorted(m.cls for m in scan(text, profile_kz()))
        self.assertEqual(classes, ["email", "iban", "iin", "iin", "phone"])

    def test_invalid_12_digits_ignored_unless_strict(self):
        bad = self.iin[:-1] + str((int(self.iin[-1]) + 1) % 10)
        # вес 11-го разряда нулевой по модулю 11, поэтому подменяем 10-ю цифру
        bad = self.iin[:9] + str((int(self.iin[9]) + 1) % 10) + self.iin[10:]
        self.assertFalse(ck.is_kz_iin(bad))
        self.assertEqual(scan(f"номер {bad}", profile_kz()), [])
        self.assertEqual(len(scan(f"номер {bad}", profile_kz(strict=True))), 1)

    def test_ru_profile(self):
        text = "ИНН 7707083893, ОГРН 1027700132195, СНИЛС 112-233-445 95, р/с 40702810900000000001"
        classes = [m.cls for m in scan(text, profile_ru())]
        self.assertEqual(classes, ["inn", "ogrn", "snils", "account"])

    def test_phone_formats_get_same_token(self):
        t = Tokenizer(SECRET, profile_kz())
        a = t.protect("+7 (701) 234-56-78")
        b = t.protect("87012345678")
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("[[phone:"))


class TokenizerTests(unittest.TestCase):
    def test_deterministic_and_secret_dependent(self):
        p = profile_kz()
        iin = ck.make_kz_iin(datetime.date(1980, 1, 2), True, random.Random(1))
        t1, t2 = Tokenizer(SECRET, p), Tokenizer(SECRET, p)
        other = Tokenizer(b"another-secret-0123456789", p)
        self.assertEqual(t1.protect(iin), t2.protect(iin))
        self.assertNotEqual(t1.protect(iin), other.protect(iin))
        self.assertNotIn(iin, t1.protect(f"клиент {iin}"))

    def test_known_names_in_free_text(self):
        t = Tokenizer(SECRET, profile_kz(), known=[("name", "Алия Сериковна Нурпеисова"), ("org", "ТОО «Ромашка»")])
        out = t.protect("Договор с ТОО «Ромашка», подписала алия  сериковна нурпеисова.")
        self.assertNotIn("Ромашка", out)
        self.assertNotIn("Нурпеисова", out.replace("name", ""))
        self.assertIn("[[org:", out)
        self.assertIn("[[name:", out)

    def test_short_secret_rejected(self):
        with self.assertRaises(ValueError):
            Tokenizer(b"short", profile_kz())

    def test_plain_numbers_and_dates_left_alone(self):
        t = Tokenizer(SECRET, profile_kz())
        text = "Сумма 1 250 000,50, документ № 000123 от 14.03.2026"
        self.assertEqual(t.protect(text), text)


class LeakCheckTests(unittest.TestCase):
    def test_detects_open_values_in_any_format(self):
        secrets = [("iin", "900412300123"), ("phone", "+7 701 234 56 78"), ("name", "Алия Нурпеисова")]
        text = "ИИН: 900412 300123; звонить 8 (701) 234-56-78; контакт алия   нурпеисова"
        self.assertEqual(len(leak_check(text, secrets)), 3)

    def test_clean_text_has_no_leaks(self):
        t = Tokenizer(SECRET, profile_kz(strict=True), known=[("name", "Алия Нурпеисова")])
        text = t.protect("Алия Нурпеисова, ИИН 900412300123, тел 87012345678")
        secrets = [("iin", "900412300123"), ("phone", "87012345678"), ("name", "Алия Нурпеисова")]
        self.assertEqual(leak_check(text, secrets), [])


if __name__ == "__main__":
    unittest.main()
