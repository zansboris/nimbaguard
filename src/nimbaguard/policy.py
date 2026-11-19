"""Politique de comportement attendu d'un agent, chargée depuis un fichier YAML."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ALL_PII = ("email", "phone", "card", "iban", "secret")


@dataclass
class ToolRule:
    name: str
    max_calls_per_minute: int | None = None
    allowed_domains: list[str] = field(default_factory=list)  # motifs, ex. "*.orange-guinee.com"
    domain_args: list[str] = field(default_factory=lambda: ["url"])
    allowed_paths: list[str] = field(default_factory=list)  # préfixes, ex. "/data/rapports/"
    path_args: list[str] = field(default_factory=lambda: ["path"])
    block_pii: list[str] = field(default_factory=list)  # données interdites dans les arguments
    require_approval: bool = False

    @classmethod
    def from_dict(cls, name: str, d: dict[str, Any] | None) -> "ToolRule":
        d = d or {}
        known = {k: v for k, v in d.items() if k in cls.__dataclass_fields__ and k != "name"}
        unknown = set(d) - set(known)
        if unknown:
            raise ValueError(f"outil '{name}' : clés inconnues {sorted(unknown)}")
        rule = cls(name=name, **known)
        bad = set(rule.block_pii) - set(ALL_PII)
        if bad:
            raise ValueError(f"outil '{name}' : types de données inconnus {sorted(bad)}")
        return rule

    def domain_allowed(self, host: str) -> bool:
        host = host.lower()
        return any(fnmatch.fnmatch(host, pat.lower()) for pat in self.allowed_domains)

    def path_allowed(self, path: str) -> bool:
        # resolve() supprime les "../" ; is_relative_to gere Windows et Linux.
        p = Path(path).resolve()
        return any(p.is_relative_to(Path(pre).resolve()) for pre in self.allowed_paths)


@dataclass
class Policy:
    agent: str
    mode: str = "enforce"  # "enforce" bloque, "monitor" journalise seulement
    default: str = "deny"  # outil absent de la liste : "deny" ou "allow"
    tools: dict[str, ToolRule] = field(default_factory=dict)
    max_calls_per_minute: int | None = None  # plafond global, tous outils confondus

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Policy":
        if "agent" not in d:
            raise ValueError("la politique doit nommer l'agent (clé 'agent')")
        mode = d.get("mode", "enforce")
        default = d.get("default", "deny")
        if mode not in ("enforce", "monitor"):
            raise ValueError("mode doit valoir 'enforce' ou 'monitor'")
        if default not in ("deny", "allow"):
            raise ValueError("default doit valoir 'deny' ou 'allow'")
        tools = {name: ToolRule.from_dict(name, spec) for name, spec in (d.get("tools") or {}).items()}
        return cls(agent=d["agent"], mode=mode, default=default, tools=tools,
                   max_calls_per_minute=d.get("max_calls_per_minute"))

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(yaml.safe_load(f) or {})

    def to_dict(self) -> dict[str, Any]:
        tools: dict[str, Any] = {}
        for name, r in self.tools.items():
            spec: dict[str, Any] = {}
            if r.max_calls_per_minute is not None:
                spec["max_calls_per_minute"] = r.max_calls_per_minute
            if r.allowed_domains:
                spec["allowed_domains"] = r.allowed_domains
            if r.allowed_paths:
                spec["allowed_paths"] = r.allowed_paths
            if r.block_pii:
                spec["block_pii"] = r.block_pii
            if r.require_approval:
                spec["require_approval"] = True
            tools[name] = spec
        out: dict[str, Any] = {"agent": self.agent, "mode": self.mode, "default": self.default}
        if self.max_calls_per_minute is not None:
            out["max_calls_per_minute"] = self.max_calls_per_minute
        out["tools"] = tools
        return out

    def dump(self) -> str:
        return yaml.safe_dump(self.to_dict(), allow_unicode=True, sort_keys=False)
