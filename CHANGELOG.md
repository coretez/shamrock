# Changelog

Notable changes to Shamrock. Dates are the release date; the objectives ledger
in [`docs/HARNESS_OBJECTIVES.md`](docs/HARNESS_OBJECTIVES.md) carries the
per-capability acceptance criteria and status.

## 0.3.0 — LLM firewall · 2026-08-25

The headline is the **LLM firewall** (objective O17): Shamrock can now route
every model call through a guard running on your own machine, act on its
verdict, and record what happened without storing what was said.

### LLM firewall

- **Guard connections** — app-global, encrypted like any provider credential.
  Add a Trylon gateway under Guards, TEST it, save, enable. An enabled guard
  changes where model traffic goes; nothing else about the turn changes.
- **A block stops the turn.** A refused prompt produces a firewall card with
  *Edit Prompt* and *View Audit* — not a chatbot answer. Blocked text is
  withheld from the token stream and never enters the transcript.
- **Direction is reported.** The card distinguishes an **outbound** block (the
  prompt never left the machine) from an **inbound** one (the model answered
  and the answer was refused). This is a real distinction, not a label: they
  have different consequences.
- **Metadata-only audit.** Decision, duration, policy code, action and the
  gateway's correlation id. Never the prompt, never the response.
- **Fails closed.** Once a turn is blocked, every later model call in that turn
  stops locally without another network round trip.
- **Rulesets ship with the app** — [`firewall/`](firewall/) holds the two
  profiles Shamrock is tested against plus setup instructions.
- `npm run firewall-suite` validates a ruleset (46 cases) against the gateway's
  `/safeguard` endpoint — no model credential, no cost. Half the suite is a
  false-positive corpus: a guard that blocks everything must fail it.
- `npm run firewall-regression` runs three real workloads end to end, guard off
  versus guard on, and diffs them.

### Ruleset findings

Regression testing against real security data produced two false positives that
no threshold could fix, both now handled:

- **Epoch-millisecond timestamps pass the Luhn checksum.** Presidio's
  credit-card recognizer *is* a 13-19 digit Luhn check, so a timestamp like
  `1786307640000` scores CREDIT_CARD at confidence **1.0**. Tool results are
  full of these. Shamrock now converts epoch-millis to ISO 8601 at the tool
  boundary — which also gives the model a date it can reason about instead of
  an integer it cannot.
- **Hex hashes contain DEA-number patterns.** `MEDICAL_LICENSE` fires on
  **3.8% of SHA-256 hashes** at confidence 1.0; a result carrying thirty hashes
  had a ~68% chance of being refused. Measured over 1,200 samples, every other
  entity in the ruleset collided zero times. That recognizer is excluded.

### Fixed

- **Uploaded HTML renders instead of showing its source.** The document viewer
  already had a render path, but it keyed on a `mime_type` nobody validated,
  and the upload handler stamped a fixed label on every file regardless of what
  it was — older rows read `text`, newer ones `text/plain`. An uploaded
  `.html` therefore failed the check and fell through to the text reader.
  The mime is now resolved from the file path at read time, which repairs rows
  already in the library without a migration, and recorded correctly on upload.
  A *specific* stored mime still wins, so PDFs continue to route to their own
  window rather than the artifact panel.
- **Work is no longer discarded when a turn is blocked.** A block on the
  seventh tool call reported `toolTrace: []` and `iterations: 0` — identical to
  a block on the first, throwing away results already paid for. Both the flat
  loop and the planned path now carry their ledger out with the error, and the
  reported token usage is the turn's aggregate rather than just the refused
  call.
- **Guards work with every OpenAI-compatible connection.** Routing was gated on
  provider *type* rather than wire *style*, which locked Qwen, Kimi and Gemini
  out of the firewall entirely — three of five connection types.
- **The gateway now states the block direction** (`X-Trylon-Stage`) instead of
  leaving Shamrock to infer it from a response-id side effect. The old
  inference worked only on the OpenAI route; on the Anthropic route an input
  and an output block are byte-identical, so direction was always unknown.
  Requires the header patch in the companion gateway; Shamrock falls back to
  the old heuristic without it.

### MCP OAuth

- **Shamrock no longer replays a spent refresh token.** Servers that rotate
  refresh tokens (OAuth 2.1 / RFC 6819 §5.2.2.3) treat a second presentation as
  evidence of theft and revoke the entire grant — so the retry was not a
  harmless retry, it was the thing that destroyed the authorization. Two bugs
  caused two replays per connect: a failed refresh was swallowed and the
  known-expired token returned anyway (guaranteeing a 401), and that 401 then
  triggered a second refresh with the same dead token.
- A revoked grant is now recognised (`invalid_grant` / replay), recorded, and
  never refreshed again. The server is marked with a plain-English
  "authorization expired — reconnect this server" instead of `HTTP 401`.
  Transient failures — a 5xx, a network drop — stay retryable.
- **Concurrent connects no longer race.** `ensure()` deduplicates in-flight
  opens, so a CONNECT click landing while a turn starts can no longer have both
  callers refresh and the loser replay the winner's spent token.

### Tooling

- `scripts/_app-identity.js` — `safeStorage` keys its keychain entry by app
  name, and a bare `electron scripts/foo.js` run silently becomes "Electron",
  so every stored API key failed to decrypt with an opaque error. `npm run
  eval` had been broken by this. Claimed centrally now, so a new script cannot
  reintroduce it.
- Script database paths derive from Electron's `userData` instead of a
  hardcoded macOS path.

### Also in this release

Work that landed since 0.2.0 alongside the firewall:

- **Archive and delete** for chats and projects, with a way back.
- **Documents page** — the two libraries as tabs rather than one stacked list.
- **Faceted library browse**, with relative windows over quarters.
- **Librarian** — sessions are titled, summarized and tagged after the reply
  returns, off the turn's critical path.

## 0.2.0 — rules become gates · 2026-08

Agent rules re-expressed as executable gates rather than prose the model is
asked to remember.

## 0.1.0 — public dev preview · 2026-08

First public release.
