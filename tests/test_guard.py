import json

import pytest

from nimbaguard import AuditLog, Blocked, Guard, Policy, learn, verify
from nimbaguard.cli import main
from nimbaguard.detectors import redact, scan


def make_policy(**over):
    d = {
        "agent": "test",
        "tools": {
            "fetch": {"allowed_domains": ["*.exemple.gn"], "block_pii": ["email", "phone", "card"]},
            "lire_fichier": {"allowed_paths": ["/tmp/autorise"]},
            "sms": {"max_calls_per_minute": 2},
            "virement": {"require_approval": True},
        },
    }
    d.update(over)
    return Policy.from_dict(d)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


# -- détecteurs ---------------------------------------------------------------

@pytest.mark.parametrize("text", ["+224 620 12 34 56", "00224620123456", "620 12 34 56", "620.12.34.56"])
def test_detecte_numeros_guineens(text):
    assert [f.kind for f in scan({"t": text}, ["phone"])] == ["phone"]


def test_carte_valide_luhn_seulement():
    assert scan("4111 1111 1111 1111", ["card"])
    assert not scan("4111 1111 1111 1112", ["card"])


def test_scan_recursif_et_secrets():
    found = scan({"a": [{"b": "contact: ami@mail.gn"}], "k": "sk-" + "x" * 24}, ["email", "secret"])
    assert {f.kind for f in found} == {"email", "secret"}


def test_redaction():
    assert redact({"m": "écrire à ami@mail.gn"}) == {"m": "écrire à [EMAIL]"}


# -- décisions ------------------------------------------------------------------

def test_outil_inconnu_refuse_par_defaut():
    d = Guard(make_policy()).evaluate("supprimer_tout", {})
    assert not d.allowed and d.rule == "outil_inconnu"


def test_outil_inconnu_autorise_si_default_allow():
    assert Guard(make_policy(default="allow")).evaluate("autre", {}).allowed


def test_domaine():
    g = Guard(make_policy())
    assert g.evaluate("fetch", {"url": "https://api.exemple.gn/x"}).allowed
    d = g.evaluate("fetch", {"url": "https://evil.com/x"})
    assert not d.allowed and d.rule == "domaine"


def test_donnees_sensibles_bloquees():
    d = Guard(make_policy()).evaluate("fetch", {"url": "https://api.exemple.gn", "q": "client 620 12 34 56"})
    assert not d.allowed and d.rule == "donnees_sensibles" and d.findings == ["phone"]


def test_chemin_et_traversee(tmp_path):
    g = Guard(make_policy())
    assert g.evaluate("lire_fichier", {"path": "/tmp/autorise/a.txt"}).allowed
    assert not g.evaluate("lire_fichier", {"path": "/tmp/autorise/../../etc/passwd"}).allowed
    assert not g.evaluate("lire_fichier", {"path": "/tmp/autorise-pas/a.txt"}).allowed


def test_debit_par_outil_fenetre_glissante():
    clock = FakeClock()
    g = Guard(make_policy(), clock=clock)
    g.check("sms")
    g.check("sms")
    with pytest.raises(Blocked) as e:
        g.check("sms")
    assert e.value.decision.rule == "debit_outil"
    clock.t = 61
    assert g.check("sms").allowed


def test_debit_global():
    g = Guard(make_policy(max_calls_per_minute=1, default="allow"), clock=FakeClock())
    g.check("a")
    with pytest.raises(Blocked):
        g.check("b")


def test_approbation_humaine():
    assert not Guard(make_policy()).evaluate("virement", {}).allowed
    assert Guard(make_policy(), approver=lambda t, a: True).evaluate("virement", {}).allowed


def test_mode_monitor_ne_bloque_pas(tmp_path):
    log = tmp_path / "a.jsonl"
    g = Guard(make_policy(mode="monitor"), audit=str(log))
    d = g.check("supprimer_tout")
    assert not d.allowed and not d.enforced
    assert json.loads(log.read_text().splitlines()[0])["decision"] == "alert"


# -- intégration --------------------------------------------------------------

def test_decorateur_sync_et_async():
    import asyncio

    g = Guard(make_policy())

    @g.wrap(name="fetch")
    def fetch(url, q=""):
        return "ok"

    @g.wrap(name="fetch")
    async def afetch(url):
        return "ok"

    assert fetch("https://a.exemple.gn") == "ok"
    with pytest.raises(Blocked):
        fetch("https://evil.com", q="x")
    assert asyncio.run(afetch("https://a.exemple.gn")) == "ok"
    with pytest.raises(Blocked):
        asyncio.run(afetch("https://evil.com"))


# -- audit ----------------------------------------------------------------------

def test_journal_chaine_et_altération(tmp_path):
    log = tmp_path / "a.jsonl"
    g = Guard(make_policy(), audit=str(log))
    g.check("fetch", {"url": "https://a.exemple.gn", "q": "bonjour"})
    with pytest.raises(Blocked):
        g.check("fetch", {"url": "https://a.exemple.gn", "q": "ami@mail.gn"})
    assert verify(log)[0]
    lines = log.read_text().splitlines()
    assert "ami@mail.gn" not in lines[1]  # le journal est expurgé
    altered = json.loads(lines[1])
    altered["decision"] = "allow"
    log.write_text(lines[0] + "\n" + json.dumps(altered) + "\n")
    ok, msg = verify(log)
    assert not ok and "modifié" in msg


def test_journal_suppression_detectee(tmp_path):
    log = tmp_path / "a.jsonl"
    a = AuditLog(log)
    for i in range(3):
        a.write({"tool": "t", "i": i})
    lines = log.read_text().splitlines()
    log.write_text(lines[0] + "\n" + lines[2] + "\n")
    assert not verify(log)[0]


def test_journal_reprend_la_chaine(tmp_path):
    log = tmp_path / "a.jsonl"
    AuditLog(log).write({"tool": "a"})
    AuditLog(log).write({"tool": "b"})
    assert verify(log) == (True, "2 entrées, chaîne intacte")


# -- apprentissage et CLI ------------------------------------------------------

def test_learn_depuis_monitor(tmp_path):
    log = tmp_path / "a.jsonl"
    g = Guard(Policy.from_dict({"agent": "x", "mode": "monitor", "default": "allow"}), audit=str(log))
    for _ in range(3):
        g.check("fetch", {"url": "https://api.exemple.gn/v1"})
    g.check("calcul", {"n": 1})
    p = learn(log)
    assert set(p.tools) == {"fetch", "calcul"}
    assert p.tools["fetch"].allowed_domains == ["api.exemple.gn"]
    assert p.tools["fetch"].max_calls_per_minute == 6
    assert Policy.from_dict(__import__("yaml").safe_load(p.dump())).tools.keys() == p.tools.keys()


def test_politique_invalide():
    with pytest.raises(ValueError):
        Policy.from_dict({"agent": "x", "tools": {"t": {"block_pii": ["adn"]}}})
    with pytest.raises(ValueError):
        Policy.from_dict({"agent": "x", "tools": {"t": {"domaines": ["a"]}}})
    with pytest.raises(ValueError):
        Policy.from_dict({"tools": {}})


def test_cli(tmp_path, capsys):
    pol = tmp_path / "p.yaml"
    pol.write_text(make_policy().dump(), encoding="utf-8")
    assert main(["check", str(pol), "fetch", '{"url": "https://evil.com"}']) == 1
    assert "BLOQUÉ" in capsys.readouterr().out
    assert main(["check", str(pol), "fetch", '{"url": "https://a.exemple.gn"}']) == 0
