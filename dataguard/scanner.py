"""Поиск и подмена чувствительных значений в тексте: профили Казахстана и России, детерминированные токены, словарь известных значений."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from . import checksums as ck

_PHONE = re.compile(r"(?<![\d+])(?:\+7|8|7)[\s\-()]*\d{3}[\s\-()]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DIGITS12 = re.compile(r"(?<!\d)\d{12}(?!\d)")
_DIGITS10_12 = re.compile(r"(?<!\d)\d{10}(?:\d{2})?(?!\d)")
_OGRN = re.compile(r"(?<!\d)(?:\d{13}|\d{15})(?!\d)")
_SNILS = re.compile(r"(?<!\d)\d{3}-\d{3}-\d{3}[ -]\d{2}(?!\d)|(?<!\d)\d{11}(?!\d)")
_KZ_IBAN = re.compile(r"(?<![A-Za-z0-9])KZ\d{2}(?:\s?[A-Z0-9]{4}){4}(?![A-Za-z0-9])", re.I)
_KZ_BIC = re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}KZ[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Za-z0-9])")
_RU_ACCOUNT = re.compile(r"(?<!\d)(?:30[12]\d{2}|40[1-8]\d{2})\d{15}(?!\d)")


@dataclass(frozen=True)
class Match:
    start: int
    end: int
    cls: str
    value: str


@dataclass
class Detector:
    cls: str
    pattern: re.Pattern
    validate: Optional[Callable[[str], bool]] = None


def _digits_only(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


@dataclass
class Profile:
    name: str
    detectors: list[Detector] = field(default_factory=list)


def profile_kz(strict: bool = False) -> Profile:
    """strict: любое 12-значное число считается ИИН/БИН, даже с неверной контрольной цифрой (меньше пропусков, больше лишних замен)."""
    return Profile("kz", [
        Detector("iin", _DIGITS12, None if strict else ck.is_kz_iin_or_bin),
        Detector("iban", _KZ_IBAN, ck.is_kz_iban),
        Detector("bic", _KZ_BIC, None),
        Detector("phone", _PHONE, None),
        Detector("email", _EMAIL, None),
    ])


def profile_ru(strict: bool = False) -> Profile:
    return Profile("ru", [
        Detector("inn", _DIGITS10_12, None if strict else ck.is_ru_inn),
        Detector("ogrn", _OGRN, None if strict else ck.is_ru_ogrn),
        Detector("snils", _SNILS, None if strict else ck.is_ru_snils),
        Detector("account", _RU_ACCOUNT, None),
        Detector("phone", _PHONE, None),
        Detector("email", _EMAIL, None),
    ])


PROFILES = {"kz": profile_kz, "ru": profile_ru}


def scan(text: str, profile: Profile) -> list[Match]:
    """Все непересекающиеся находки по профилю; при пересечении остается более длинная."""
    found: list[Match] = []
    for det in profile.detectors:
        for m in det.pattern.finditer(text):
            raw = m.group(0)
            if det.validate and not det.validate(raw):
                continue
            found.append(Match(m.start(), m.end(), det.cls, raw))
    found.sort(key=lambda x: (x.start, -(x.end - x.start)))
    out: list[Match] = []
    last_end = -1
    for m in found:
        if m.start >= last_end:
            out.append(m)
            last_end = m.end
    return out


def _normalize(cls: str, value: str) -> str:
    if cls in ("iin", "inn", "ogrn", "snils", "account"):
        return _digits_only(value)
    if cls == "phone":
        d = _digits_only(value)
        return d[-10:] if len(d) >= 10 else d
    if cls in ("iban", "bic"):
        return value.replace(" ", "").upper()
    return value.strip().lower()


class Tokenizer:
    """Подменяет значения токенами вида [[iin:M4T2Q9XZ7K]]: одно значение всегда дает один токен, секрет известен только шлюзу."""

    def __init__(self, secret: bytes, profile: Profile, known: Iterable[tuple[str, str]] = ()):
        if len(secret) < 16:
            raise ValueError("Секрет токенов должен быть не короче 16 байт")
        self._secret = secret
        self.profile = profile
        self._known: list[tuple[str, str]] = []
        self._known_re: Optional[re.Pattern] = None
        self.add_known(known)

    def token(self, cls: str, value: str) -> str:
        digest = hmac.new(self._secret, f"{cls}\x00{_normalize(cls, value)}".encode("utf-8"), hashlib.sha256).digest()
        return f"[[{cls}:{base64.b32encode(digest)[:10].decode('ascii')}]]"

    def add_known(self, items: Iterable[tuple[str, str]]) -> None:
        """Значения, найденные в базе заранее (ФИО, названия организаций): ловятся в свободном тексте без шаблона."""
        for cls, value in items:
            v = " ".join(str(value).split())
            if len(v) >= 4 and (cls, v) not in self._known:
                self._known.append((cls, v))
        if self._known:
            ordered = sorted(self._known, key=lambda kv: -len(kv[1]))
            alt = "|".join(re.escape(v).replace(r"\ ", r"\s+") for _, v in ordered)
            self._known_re = re.compile(r"(?<![\w])(?:" + alt + r")(?![\w])", re.I | re.U)

    def _known_cls(self, value: str) -> str:
        norm = " ".join(value.split()).lower()
        for cls, v in self._known:
            if v.lower() == norm:
                return cls
        return "name"

    def protect(self, text: str) -> str:
        spans: list[tuple[int, int, str]] = []
        if self._known_re:
            for m in self._known_re.finditer(text):
                cls = self._known_cls(m.group(0))
                spans.append((m.start(), m.end(), self.token(cls, m.group(0))))
        for m in scan(text, self.profile):
            if not any(s <= m.start < e or s < m.end <= e for s, e, _ in spans):
                spans.append((m.start, m.end, self.token(m.cls, m.value)))
        for s, e, tok in sorted(spans, reverse=True):
            text = text[:s] + tok + text[e:]
        return text


def leak_check(text: str, secrets: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    """Какие из заведомо реальных значений (cls, значение) присутствуют в тексте открыто. Пусто - утечки нет."""
    flat = re.sub(r"\s+", " ", text).lower()
    digits = _digits_only(text)
    leaked: list[tuple[str, str]] = []
    for cls, value in secrets:
        norm = _normalize(cls, value)
        if cls in ("iin", "inn", "ogrn", "snils", "account", "phone"):
            hit = bool(norm) and norm in digits
        else:
            hit = " ".join(str(value).split()).lower() in flat
        if hit:
            leaked.append((cls, value))
    return leaked
