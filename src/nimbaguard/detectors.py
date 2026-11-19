"""Détection de données sensibles dans les arguments d'un appel d'outil.

Les détecteurs sont volontairement simples (expressions régulières + contrôle
de Luhn) : ils servent à bloquer les fuites évidentes, pas à remplacer un DLP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# Numéros guinéens : +224 / 00224 facultatif, puis 9 chiffres commençant par 6
# (mobiles) ou 3 (fixes), avec espaces ou points éventuels.
PHONE_GN = re.compile(r"(?<!\d)(?:(?:\+|00)224[\s.-]?)?[36]\d{2}(?:[\s.-]?\d{2}){3}(?!\d)")
# Numéro international générique (+ suivi de 8 à 15 chiffres).
PHONE_INTL = re.compile(r"(?<![\w+])\+\d[\d\s.-]{7,17}\d")
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
SECRET = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[bap]-[A-Za-z0-9-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str


def _luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iter_strings(value: Any) -> Iterator[str]:
    """Parcourt récursivement une structure (dict, list, str...) et rend ses chaînes."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from iter_strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from iter_strings(v)
    elif value is not None:
        yield str(value)


def scan_text(text: str, kinds: Iterable[str]) -> list[Finding]:
    kinds = set(kinds)
    found: list[Finding] = []
    if "email" in kinds:
        found += [Finding("email", m.group()) for m in EMAIL.finditer(text)]
    if "phone" in kinds:
        seen = set()
        for rx in (PHONE_GN, PHONE_INTL):
            for m in rx.finditer(text):
                if m.group() not in seen:
                    seen.add(m.group())
                    found.append(Finding("phone", m.group()))
    if "card" in kinds:
        for m in CARD.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                found.append(Finding("card", m.group()))
    if "iban" in kinds:
        found += [Finding("iban", m.group()) for m in IBAN.finditer(text)]
    if "secret" in kinds:
        found += [Finding("secret", m.group()) for m in SECRET.finditer(text)]
    return found


def scan(value: Any, kinds: Iterable[str]) -> list[Finding]:
    kinds = list(kinds)
    out: list[Finding] = []
    for s in iter_strings(value):
        out += scan_text(s, kinds)
    return out


def redact(value: Any, kinds: Iterable[str] = ("email", "phone", "card", "iban", "secret")) -> Any:
    """Copie de `value` où les données sensibles sont masquées (pour le journal d'audit)."""
    kinds = list(kinds)
    if isinstance(value, str):
        out = value
        for f in sorted(scan_text(value, kinds), key=lambda f: -len(f.value)):
            out = out.replace(f.value, f"[{f.kind.upper()}]")
        return out
    if isinstance(value, dict):
        return {k: redact(v, kinds) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v, kinds) for v in value]
    return value
