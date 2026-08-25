# LLM Firewall — gateway rulesets

Shamrock's LLM firewall is not built in. It routes model traffic through a
**[Trylon Gateway](https://github.com/trylonai/gateway)** running on your own
machine, and Trylon decides. Shamrock's job is to route to it, act on the
verdict, and record what happened without storing the content.

This directory holds the rulesets Shamrock is developed and tested against.
They are Trylon `policies.yaml` files — copy one into your gateway checkout.

## Setup

```bash
git clone https://github.com/trylonai/gateway.git
cd gateway
uv sync
cp /path/to/shamrock/firewall/policies.yaml policies.yaml
uv run python -m src.main          # listens on :8000
```

Then in Shamrock: **Guards → add a Trylon guard → `http://localhost:8000/v1`
→ TEST → save → enable.**

The gateway reloads `policies.yaml` when the file's mtime changes, so ruleset
edits do not need a restart. Model downloads on first launch are ~1.5GB.

## The two profiles

| | `policies.yaml` (default) | `policies.soc.yaml` |
|---|---|---|
| Email, phone, IP, URL | **blocked** | allowed |
| Regulated + financial IDs | blocked | blocked |
| Credentials, injection, internals | blocked | blocked |
| Competitor / person / location / toxicity | observed | observed |

`policies.yaml` is what the walkthrough demonstrates and what most people mean
by "LLM firewall" — do not paste a customer's email address into a third-party
model.

`policies.soc.yaml` is for putting the gateway in front of security-operations
work, where an analyst has to be able to type an IP address and name a mailbox.
Select it with `POLICIES_FILE_PATH=policies.soc.yaml`.

## Testing a ruleset

```bash
scripts/firewall-suite.sh              # default profile
FW_PROFILE=soc scripts/firewall-suite.sh
```

46 cases against the gateway's `/safeguard` endpoint — no model credential
needed, no cost. Half of them are true positives; the other half is a
false-positive corpus of ordinary language the ruleset must NOT catch. A guard
that blocks everything passes the first half and fails the product.

## Why some recognizers are deliberately absent

Both profiles exclude three Presidio recognizers, on measurements rather than
taste. The reasoning is in the comments of `policies.yaml`; briefly:

- **`MEDICAL_LICENSE`** matches a DEA-number pattern that occurs inside random
  hexadecimal, scoring 1.0 when it does — measured at **3.8% of SHA-256 hashes**.
- **`US_BANK_NUMBER`** reaches its 0.40 ceiling on any 8-17 digit run near the
  word "account", which describes most log identifiers.
- **`US_DRIVER_LICENSE`** scores 0.01 on arbitrary digit strings and can never
  clear the threshold, so listing it implies coverage that does not exist.

`pii_threshold: 0.45` is likewise a measured boundary, not a round number — see
the comment on the entity list before changing it.

One thing the gateway cannot do: match high-entropy secrets. Trylon has no
regex policy type and Presidio has no secret recognizer, so a random key body
(`sk-proj-<40 chars>`) cannot be caught by fuzzy comparison. The rulesets cover
the labelled config lines and key headers that carry them; anything stronger
belongs in Shamrock's own outbound path.
