# nimbaguard

**Français** · [English](README.en.md)

**Pare-feu comportemental pour agents IA.** Un agent peut avoir la permission d'utiliser un outil et l'utiliser quand même de façon dangereuse : envoyer des données clients vers un site externe, déclencher un virement, s'emballer et faire 500 appels par minute. `nimbaguard` décrit ce que l'agent est *censé* faire, bloque tout le reste avant exécution, et garde une trace infalsifiable de chaque décision.

Conçu à Conakry, pour les banques, les opérateurs et les fintechs d'Afrique de l'Ouest.

## Ce que fait la v0.1

| Contrôle | Exemple |
| --- | --- |
| Liste blanche d'outils | L'agent ne peut appeler que les outils déclarés (`default: deny`) |
| Domaines autorisés | `lire_faq` ne peut contacter que `*.ma-banque.gn` |
| Chemins autorisés | `lire_fichier` reste dans `/data/rapports/` (traversée `../` bloquée) |
| Données sensibles | E-mails, numéros guinéens (+224), cartes (contrôle de Luhn), IBAN, clés d'API |
| Débit | Plafond d'appels par minute, par outil et global |
| Validation humaine | `virement` exige l'accord d'une personne |
| Mode observation | `mode: monitor` journalise les violations sans bloquer |
| Journal d'audit chaîné | Chaque entrée contient l'empreinte SHA-256 de la précédente ; toute modification est détectée. Les données sensibles y sont masquées |
| Apprentissage | `nimbaguard learn` propose une politique à partir de ce que l'agent a réellement fait |

## Installation

```bash
pip install -e .            # dépendance unique : PyYAML
pip install -e ".[dev]"     # + pytest
```

## Utilisation

**1. Décrire le comportement attendu** (`politique.yaml`) :

```yaml
agent: assistant-client-banque
mode: enforce
default: deny
tools:
  lire_faq:
    allowed_domains: ["*.ma-banque.gn"]
    block_pii: [email, phone, card, iban, secret]
  envoyer_sms:
    max_calls_per_minute: 5
    block_pii: [card, iban, secret]
  virement:
    require_approval: true
```

**2. Protéger les outils de l'agent :**

```python
from nimbaguard import Guard, Policy, Blocked

guard = Guard(Policy.load("politique.yaml"), audit="audit.jsonl",
              approver=lambda tool, args: demander_validation(tool, args))

@guard.wrap
def lire_faq(url: str, question: str): ...

@guard.wrap(name="virement")
async def faire_virement(compte: str, montant_gnf: int): ...

try:
    lire_faq("https://pastebin.com/raw", "client 620 12 34 56")
except Blocked as e:
    print(e.decision.reason)   # domaine non autorisé : pastebin.com
```

Pour un framework d'agents (LangChain, LlamaIndex, SDK OpenAI ou Anthropic), appelez `guard.check(nom_outil, arguments)` juste avant d'exécuter l'outil demandé par le modèle.

**3. En ligne de commande :**

```bash
nimbaguard check politique.yaml lire_faq '{"url": "https://evil.com"}'   # BLOQUÉ [domaine] ...
nimbaguard verify audit.jsonl                                           # OK : 42 entrées, chaîne intacte
nimbaguard learn audit.jsonl --margin 2 > politique-proposee.yaml
```

**Démarche conseillée :** déployer en `mode: monitor` une à deux semaines, générer la politique avec `learn`, la relire, puis passer en `mode: enforce`.

## Démonstration

```bash
PYTHONPATH=src python examples/demo.py
```

```
OK      FAQ autorisée -> (réponse de https://faq.ma-banque.gn/frais)
BLOQUÉ  Exfiltration vers un site externe -> domaine non autorisé : pastebin.com
BLOQUÉ  Numéro de carte par SMS -> données sensibles dans les arguments : card
BLOQUÉ  Virement sans validation humaine -> approbation humaine requise et non obtenue

Journal : 4 entrées, chaîne intacte
```

## Limites connues

- Les détecteurs de données sensibles reposent sur des expressions régulières : ils arrêtent les fuites évidentes, pas une donnée encodée ou découpée.
- Le contrôle porte sur les arguments des appels, pas sur le contenu des réponses renvoyées au modèle.
- Le journal chaîné prouve qu'il n'a pas été modifié *depuis* son écriture, pas que la machine qui l'écrit est saine. Pour une preuve externe, publiez régulièrement la dernière empreinte ailleurs.

## Feuille de route

- Proxy MCP : protéger n'importe quel agent sans modifier son code
- Détection d'injection de prompt dans les contenus lus par l'agent
- Profil comportemental statistique (séquences d'outils inhabituelles)
- Rapports de conformité prêts à remettre (Loi L/2016/037/AN en Guinée, et équivalents régionaux)

## Licence

Apache 2.0
