"""Profil comportemental : propose une politique à partir d'un journal observé.

Faites tourner l'agent en mode `monitor` quelques jours, puis générez une
politique qui n'autorise que ce qu'il a réellement fait, avec une marge.
"""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .audit import read_entries
from .policy import ALL_PII, Policy, ToolRule


def learn(log_path: str | Path, agent: str | None = None, margin: float = 2.0) -> Policy:
    per_minute: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    domains: dict[str, set[str]] = defaultdict(set)
    seen_agent = None
    for e in read_entries(log_path):
        if agent and e.get("agent") != agent:
            continue
        if e.get("decision") == "block":  # on n'apprend que ce que l'agent a réellement fait
            continue
        seen_agent = seen_agent or e.get("agent")
        tool = e["tool"]
        minute = datetime.fromisoformat(e["ts"]).strftime("%Y-%m-%dT%H:%M")
        per_minute[tool][minute] += 1
        url = (e.get("args") or {}).get("url")
        if isinstance(url, str):
            host = urlparse(url).hostname
            if host:
                domains[tool].add(host)

    tools = {}
    for tool, minutes in per_minute.items():
        peak = max(minutes.values())
        tools[tool] = ToolRule(
            name=tool,
            max_calls_per_minute=max(1, math.ceil(peak * margin)),
            allowed_domains=sorted(domains[tool]),
            block_pii=list(ALL_PII) if domains[tool] else [],
        )
    return Policy(agent=agent or seen_agent or "agent", mode="enforce", default="deny", tools=tools)
