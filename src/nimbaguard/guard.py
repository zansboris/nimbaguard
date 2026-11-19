"""Le pare-feu : vérifie chaque appel d'outil contre la politique avant qu'il ne s'exécute."""

from __future__ import annotations

import functools
import inspect
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from .audit import AuditLog
from .detectors import redact, scan
from .policy import Policy


class Blocked(PermissionError):
    """Levée quand le pare-feu refuse un appel d'outil (mode enforce)."""

    def __init__(self, decision: "Decision"):
        super().__init__(f"[nimbaguard] {decision.tool} bloqué : {decision.reason}")
        self.decision = decision


@dataclass
class Decision:
    tool: str
    allowed: bool
    rule: str = "ok"
    reason: str = "conforme à la politique"
    findings: list[str] = field(default_factory=list)
    enforced: bool = True  # False en mode monitor : la violation est journalisée, pas bloquée


Approver = Callable[[str, dict[str, Any]], bool]


class Guard:
    def __init__(self, policy: Policy, audit: AuditLog | str | None = None,
                 approver: Approver | None = None, clock: Callable[[], float] = time.monotonic):
        self.policy = policy
        self.audit = AuditLog(audit) if isinstance(audit, str) else audit
        self.approver = approver
        self._clock = clock
        self._calls: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    # -- vérification -------------------------------------------------------
    def _rate_ok(self, key: str, limit: int | None, now: float) -> bool:
        if limit is None:
            return True
        q = self._calls[key]
        while q and now - q[0] >= 60:
            q.popleft()
        return len(q) < limit

    def evaluate(self, tool: str, args: dict[str, Any]) -> Decision:
        """Décide sans rien exécuter ni journaliser."""
        rule = self.policy.tools.get(tool)
        if rule is None and self.policy.default == "deny":
            return Decision(tool, False, "outil_inconnu", "outil absent de la politique de cet agent")

        now = self._clock()
        with self._lock:
            if not self._rate_ok("*", self.policy.max_calls_per_minute, now):
                return Decision(tool, False, "debit_global", "trop d'appels par minute (tous outils)")
        if rule is None:
            return Decision(tool, True)
        with self._lock:
            if not self._rate_ok(tool, rule.max_calls_per_minute, now):
                return Decision(tool, False, "debit_outil",
                                f"plus de {rule.max_calls_per_minute} appels par minute")

        if rule.allowed_domains:
            for name in rule.domain_args:
                if name in args and args[name]:
                    host = urlparse(str(args[name])).hostname or ""
                    if not rule.domain_allowed(host):
                        return Decision(tool, False, "domaine", f"domaine non autorisé : {host or '?'}")

        if rule.allowed_paths:
            for name in rule.path_args:
                if name in args and args[name] and not rule.path_allowed(str(args[name])):
                    return Decision(tool, False, "chemin", f"chemin hors périmètre : {args[name]}")

        if rule.block_pii:
            findings = scan(args, rule.block_pii)
            if findings:
                kinds = sorted({f.kind for f in findings})
                return Decision(tool, False, "donnees_sensibles",
                                "données sensibles dans les arguments : " + ", ".join(kinds), kinds)

        if rule.require_approval:
            if self.approver is None or not self.approver(tool, args):
                return Decision(tool, False, "approbation", "approbation humaine requise et non obtenue")

        return Decision(tool, True)

    def check(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        """Vérifie, compte l'appel, journalise, et lève `Blocked` si la politique l'impose."""
        args = args or {}
        d = self.evaluate(tool, args)
        if not d.allowed and self.policy.mode == "monitor":
            d.enforced = False
        if d.allowed or not d.enforced:
            with self._lock:
                now = self._clock()
                self._calls["*"].append(now)
                self._calls[tool].append(now)
        if self.audit is not None:
            self.audit.write({
                "agent": self.policy.agent, "tool": tool, "args": redact(args),
                "decision": "allow" if d.allowed else ("block" if d.enforced else "alert"),
                "rule": d.rule, "reason": d.reason,
            })
        if not d.allowed and d.enforced:
            raise Blocked(d)
        return d

    # -- intégration --------------------------------------------------------
    def wrap(self, func: Callable | None = None, *, name: str | None = None):
        """Décorateur : `@guard.wrap` ou `@guard.wrap(name="envoyer_email")`."""

        def deco(f: Callable):
            tool = name or f.__name__
            sig = inspect.signature(f)

            def bound_args(*a, **kw) -> dict[str, Any]:
                b = sig.bind_partial(*a, **kw)
                return dict(b.arguments)

            if inspect.iscoroutinefunction(f):
                @functools.wraps(f)
                async def aw(*a, **kw):
                    self.check(tool, bound_args(*a, **kw))
                    return await f(*a, **kw)
                return aw

            @functools.wraps(f)
            def w(*a, **kw):
                self.check(tool, bound_args(*a, **kw))
                return f(*a, **kw)
            return w

        return deco(func) if func is not None else deco
