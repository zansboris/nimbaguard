"""Démonstration : un agent bancaire tente quatre actions, le pare-feu en bloque trois.

    python examples/demo.py
"""

from pathlib import Path

from nimbaguard import Blocked, Guard, Policy, verify

HERE = Path(__file__).parent
LOG = HERE / "audit-demo.jsonl"
LOG.unlink(missing_ok=True)

guard = Guard(Policy.load(HERE / "politique-chatbot-banque.yaml"), audit=str(LOG),
              approver=lambda tool, args: False)  # personne n'a validé


@guard.wrap
def lire_faq(url: str, question: str) -> str:
    return f"(réponse de {url})"


@guard.wrap
def envoyer_sms(numero: str, texte: str) -> str:
    return "envoyé"


@guard.wrap
def virement(compte: str, montant_gnf: int) -> str:
    return "exécuté"


essais = [
    ("FAQ autorisée", lambda: lire_faq("https://faq.ma-banque.gn/frais", "frais de tenue de compte")),
    ("Exfiltration vers un site externe", lambda: lire_faq("https://pastebin.com/raw", "client 620 12 34 56")),
    ("Numéro de carte par SMS", lambda: envoyer_sms("+224 620 12 34 56", "Votre carte 4111 1111 1111 1111")),
    ("Virement sans validation humaine", lambda: virement("GN00123", 5_000_000)),
]

for titre, action in essais:
    try:
        print(f"OK      {titre} -> {action()}")
    except Blocked as e:
        print(f"BLOQUÉ  {titre} -> {e.decision.reason}")

print("\nJournal :", verify(LOG)[1])
