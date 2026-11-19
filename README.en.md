# nimbaguard

[Français](README.md) · **English**

**A behavioral firewall for AI agents.** An agent can have permission to use a tool and still use it dangerously: send customer data to an outside site, trigger a bank transfer, or run away and make 500 calls a minute. `nimbaguard` describes what the agent is *supposed* to do, blocks everything else before it runs, and keeps a tamper-evident record of every decision.

Built in Conakry, Guinea, for banks, telecom operators and fintechs in West Africa.

## What v0.1 does

| Control | Example |
| --- | --- |
| Tool allowlist | The agent can only call declared tools (`default: deny`) |
| Allowed domains | `lire_faq` can only reach `*.ma-banque.gn` |
| Allowed paths | `lire_fichier` stays inside `/data/rapports/` (`../` traversal is blocked) |
| Sensitive data | Emails, Guinean phone numbers (+224), card numbers (Luhn check), IBANs, API keys |
| Rate limits | Max calls per minute, per tool and overall |
| Human approval | `virement` (transfer) requires a person to approve it |
| Monitor mode | `mode: monitor` logs violations without blocking |
| Hash-chained audit log | Each entry holds the SHA-256 hash of the previous one, so any edit is detected. Sensitive data is masked in the log |
| Learning | `nimbaguard learn` proposes a policy from what the agent actually did |

## Installation

```bash
pip install -e .            # single dependency: PyYAML
pip install -e ".[dev]"     # + pytest
```

## Usage

**1. Describe the expected behavior** (`policy.yaml`):

```yaml
agent: bank-customer-assistant
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

**2. Protect the agent's tools:**

```python
from nimbaguard import Guard, Policy, Blocked

guard = Guard(Policy.load("policy.yaml"), audit="audit.jsonl",
              approver=lambda tool, args: ask_a_human(tool, args))

@guard.wrap
def lire_faq(url: str, question: str): ...

@guard.wrap(name="virement")
async def make_transfer(account: str, amount_gnf: int): ...

try:
    lire_faq("https://pastebin.com/raw", "customer 620 12 34 56")
except Blocked as e:
    print(e.decision.reason)   # domaine non autorisé : pastebin.com
```

With an agent framework (LangChain, LlamaIndex, OpenAI or Anthropic SDKs), call `guard.check(tool_name, arguments)` right before running the tool the model asked for.

**3. From the command line:**

```bash
nimbaguard check policy.yaml lire_faq '{"url": "https://evil.com"}'
nimbaguard verify audit.jsonl
nimbaguard learn audit.jsonl --margin 2 > proposed-policy.yaml
```

**Recommended approach:** run in `mode: monitor` for one or two weeks, generate a policy with `learn`, review it, then switch to `mode: enforce`.

Messages and decision reasons are in French for now. English messages are on the roadmap.

## Demo

```bash
PYTHONPATH=src python examples/demo.py
```

A bank agent tries four actions. Three are blocked: sending customer data to an outside site, texting a card number, and a transfer nobody approved.

## Known limits

- Sensitive-data detectors use regular expressions: they stop obvious leaks, not encoded or split data.
- Checks apply to call arguments, not to the content returned to the model.
- The hash chain proves the log has not been edited *since* it was written, not that the machine writing it is healthy. For outside proof, publish the latest hash somewhere else on a regular basis.

## Roadmap

- MCP proxy: protect any agent without changing its code
- Prompt-injection detection in content the agent reads
- Statistical behavior profiles (unusual tool sequences)
- Ready-to-submit compliance reports (Guinea's Law L/2016/037/AN, Nigeria's NDPA, Ghana's Data Protection Act, South Africa's POPIA, Kenya's Data Protection Act)
- English messages and phone/ID detectors for Nigeria, Ghana, Kenya and South Africa

## License

Apache 2.0
