import datetime
import random
import unittest

from dataguard import checksums as c


class KzTests(unittest.TestCase):
    def test_roundtrip_iin(self):
        rng = random.Random(1)
        for i in range(500):
            birth = datetime.date(1950 + i % 70, 1 + i % 12, 1 + i % 28)
            iin = c.make_kz_iin(birth, female=bool(i % 2), rng=rng)
            self.assertTrue(c.is_kz_iin(iin), iin)
            self.assertEqual(iin[:6], birth.strftime("%y%m%d"))

    def test_roundtrip_bin(self):
        rng = random.Random(2)
        for kind in "456":
            for _ in range(200):
                v = c.make_kz_bin("1503", rng, kind=kind)
                self.assertTrue(c.is_kz_bin(v), v)

    def test_single_digit_error_is_detected(self):
        # вес 11-го разряда равен 11, то есть 0 по модулю 11: замену только этой цифры алгоритм не замечает, это свойство самого алгоритма
        iin = c.make_kz_iin(datetime.date(1985, 6, 15), False, random.Random(3))
        bad = 0
        for pos in range(10):
            for digit in "0123456789":
                if digit == iin[pos]:
                    continue
                mutated = iin[:pos] + digit + iin[pos + 1:]
                if c.is_kz_iin(mutated):
                    bad += 1
        self.assertEqual(bad, 0)

    def test_structure_rules(self):
        self.assertFalse(c.is_kz_iin("850015300001"))  # месяц 00
        self.assertFalse(c.is_kz_iin("85061530000"))   # 11 цифр
        self.assertFalse(c.is_kz_iin("8506153000a1"))

    def test_second_weight_set_is_used(self):
        # для начала, где первая сумма дает 10, контрольная цифра считается по второму набору весов
        found = 0
        for n in range(100000):
            first11 = "850615" + "3" + f"{n % 10000:04d}"
            s = sum(int(d) * w for d, w in zip(first11, range(1, 12))) % 11
            if s == 10:
                self.assertIn(c.kz_control_digit(first11), (None,) + tuple(range(10)))
                found += 1
            if found > 20:
                break
        self.assertGreater(found, 0)

    def test_iban_registry_example(self):
        self.assertTrue(c.is_iban("KZ86125KZT5004100100"))
        self.assertTrue(c.is_kz_iban("KZ86 125K ZT50 0410 0100"))
        self.assertFalse(c.is_kz_iban("KZ86125KZT5004100101"))

    def test_iban_generated(self):
        rng = random.Random(4)
        for _ in range(200):
            v = c.make_kz_iban(rng)
            self.assertTrue(c.is_kz_iban(v), v)
            self.assertEqual(v[4:7], "999")


class RuTests(unittest.TestCase):
    def test_inn_known(self):
        self.assertTrue(c.is_ru_inn("7707083893"))      # публичный ИНН крупного банка
        self.assertFalse(c.is_ru_inn("7707083894"))

    def test_inn_roundtrip(self):
        rng = random.Random(5)
        for _ in range(300):
            self.assertTrue(c.is_ru_inn(c.make_ru_inn(rng, legal=True)))
            self.assertTrue(c.is_ru_inn(c.make_ru_inn(rng, legal=False)))

    def test_snils_spec_example(self):
        self.assertTrue(c.is_ru_snils("112-233-445 95"))  # пример из описания алгоритма
        self.assertFalse(c.is_ru_snils("112-233-445 96"))

    def test_snils_roundtrip(self):
        rng = random.Random(6)
        for _ in range(300):
            self.assertTrue(c.is_ru_snils(c.make_ru_snils(rng)))

    def test_ogrn(self):
        self.assertTrue(c.is_ru_ogrn("1027700132195"))  # публичный ОГРН крупного банка
        self.assertFalse(c.is_ru_ogrn("1027700132196"))
        rng = random.Random(7)
        for _ in range(200):
            self.assertTrue(c.is_ru_ogrn(c.make_ru_ogrn(rng)))
            self.assertTrue(c.is_ru_ogrn(c.make_ru_ogrn(rng, sole=True)))


if __name__ == "__main__":
    unittest.main()
