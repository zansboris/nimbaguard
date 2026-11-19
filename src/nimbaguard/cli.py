"""Ligne de commande : nimbaguard check | verify | learn"""

from __future__ import annotations

import argparse
import json
import sys

from . import audit
from .baseline import learn
from .guard import Guard
from .policy import Policy


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nimbaguard", description="Pare-feu comportemental pour agents IA")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="tester un appel d'outil contre une politique")
    c.add_argument("policy")
    c.add_argument("tool")
    c.add_argument("args", nargs="?", default="{}", help="arguments en JSON")

    v = sub.add_parser("verify", help="vérifier l'intégrité d'un journal d'audit")
    v.add_argument("log")

    lr = sub.add_parser("learn", help="proposer une politique à partir d'un journal observé")
    lr.add_argument("log")
    lr.add_argument("--agent")
    lr.add_argument("--margin", type=float, default=2.0, help="marge sur le débit observé (défaut 2)")

    a = p.parse_args(argv)
    if a.cmd == "check":
        d = Guard(Policy.load(a.policy)).evaluate(a.tool, json.loads(a.args))
        print(("AUTORISÉ" if d.allowed else "BLOQUÉ") + f" [{d.rule}] {d.reason}")
        return 0 if d.allowed else 1
    if a.cmd == "verify":
        ok, msg = audit.verify(a.log)
        print(("OK : " if ok else "ALTÉRÉ : ") + msg)
        return 0 if ok else 2
    if a.cmd == "learn":
        sys.stdout.write(learn(a.log, agent=a.agent, margin=a.margin).dump())
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
