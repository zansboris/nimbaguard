"""Journal d'audit chaîné : chaque entrée contient l'empreinte de la précédente.

Modifier ou supprimer une ligne casse la chaîne, ce que `verify` détecte.
C'est la piste d'audit à montrer à un client ou à un régulateur.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._prev = GENESIS
        if self.path.exists():
            for entry in read_entries(self.path):
                self._prev = entry.get("hash", self._prev)

    def write(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **record,
                     "prev": self._prev}
            entry["hash"] = _digest(entry)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._prev = entry["hash"]
            return entry


def read_entries(path: str | Path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def verify(path: str | Path) -> tuple[bool, str]:
    """Vérifie l'intégrité de la chaîne. Rend (ok, message)."""
    prev = GENESIS
    n = 0
    for n, entry in enumerate(read_entries(path), start=1):
        if entry.get("prev") != prev:
            return False, f"ligne {n} : chaîne rompue (une entrée a été supprimée ou insérée)"
        if entry.get("hash") != _digest(entry):
            return False, f"ligne {n} : contenu modifié après écriture"
        prev = entry["hash"]
    return True, f"{n} entrées, chaîne intacte"
