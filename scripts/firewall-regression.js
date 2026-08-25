'use strict';

// LLM FIREWALL REGRESSION HARNESS
//
// firewall-suite.sh answers "does the RULESET decide correctly?" against
// Trylon's /safeguard endpoint. This answers the other half: "does SHAMROCK
// behave correctly when a real turn, with real MCP tools, meets a real guard?"
//
// It runs three representative workloads end to end through the same
// guardedConnector + runChatLoop path the app uses, once with the guard OFF
// (control) and once with it ON, and diffs the two.
//
//   npm run firewall-regression
//
// Costs real API calls. Not part of `npm test`.

const { liveDbPath } = require('./_app-identity'); // MUST come first — see the file for why

const { app } = require('electron');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const GUARD_URL = process.env.TRYLON_URL || 'http://127.0.0.1:8000/v1';

const WORKLOADS = [
  {
    id: 'flowchart',
    label: 'High-level harness flowchart',
    tools: false,
    prompt: 'Create a high level flowchart explaining how the harness is designed to work. Use a mermaid diagram plus a short paragraph per stage.'
  },
  {
    id: 'monthly-report',
    label: 'Expo monthly report — August',
    tools: true,
    prompt: 'Produce a monthly security operations report for the Expo tenant covering August 2026. Include case volume, severity mix, and the notable incidents.'
  },
  {
    id: 'incidents',
    label: 'Investigate last 5 Expo incidents',
    tools: true,
    prompt: 'Investigate the last 5 incidents in the Expo tenant. For each, give the affected entity, what fired, and whether it looks like a true positive.'
  }
];

// The LIVE database, deliberately.
//
// The first version of this harness ran against a throwaway copy, which looks
// safer and is not: MCP OAuth refresh tokens are single-use and ROTATE. A run
// against a copy spends the live refresh token and writes its replacement into
// the copy, so the next run replays a dead token and the server invalidates the
// grant — the user has to re-authorize the MCP server by hand. Token rotation
// has to land where the app will look for it.
//
// Nothing else here writes: the guard is an in-memory object (getConnector
// takes a plain object, not a row) and onAudit collects into an array, so no
// guard rows, audit rows or metrics rows are created.
function openLiveDb() {
  const live = liveDbPath();
  const backup = `${live}.bak-firewall-regression`;
  fs.copyFileSync(live, backup);
  console.log(`db: ${live}\n    backup at ${backup}\n`);
  require('../src/main/db').openDatabase(live);
  return require('../src/main/db/repo');
}

/** The connection the app itself is configured with. */
function resolveProvider(repo) {
  const provider = repo.providers.list().find((p) => p.enabled);
  if (!provider) throw new Error('no enabled provider — connect one in the app first');
  const key = repo.providers.reveal(provider.id);
  if (!key) throw new Error(`no API key stored for ${provider.label || provider.type}`);
  const model = process.env.FW_MODEL || provider.default_model || provider.fast_model;
  if (!model) throw new Error('no model on the connection — set one in the app first');
  return { provider, key, model };
}

/** An in-memory guard — same shape getConnector reads off a row, no write. */
function makeGuard() {
  return { enabled: true, kind: 'trylon', label: 'Local Trylon', base_url: GUARD_URL, auth_mode: 'passthrough' };
}

/** One workload, one guard setting. Returns everything worth diffing. */
async function runOnce({ repo, provider, key, model, guard, workload, toolset }) {
  const { getConnector } = require('../src/main/providers');
  const { runChatLoop } = require('../src/main/chat-loop');
  const audit = [];
  const events = [];
  const connector = getConnector(provider, key, {
    guard, guardKey: null,
    onAudit: (row) => { audit.push(row); return audit.length; }
  });

  let security = null;
  let blockedPayload = null;
  const chat = async (a) => {
    const r = await connector.chat(a);
    if (r && r.security && r.security.blocked) {
      security = r.security;
      // Keep exactly what was on the wire when the guard refused. Without this
      // a block is a verdict with no evidence, and tuning the ruleset becomes
      // guesswork.
      blockedPayload = (a.messages || []).map((m) => ({ role: m.role, name: m.name || null, content: String(m.content || '') }));
      const e = new Error(r.security.message); e.code = 'LLM_GUARD_BLOCKED'; throw e;
    }
    return r;
  };

  const started = Date.now();
  try {
    const result = await runChatLoop({
      chat, model,
      callTool: toolset ? (name, args) => toolset.call(name, args) : async () => ({ text: '', isError: true }),
      messages: [{ role: 'user', content: workload.prompt }],
      tools: toolset ? toolset.tools : [],
      maxIters: 12,
      onEvent: (e) => { if (e.type !== 'token') events.push(e); }
    });
    return { ok: true, blocked: false, durationMs: Date.now() - started, audit, events, security,
             reply: result.reply || '', toolTrace: result.toolTrace || [], iterations: result.iterations, usage: result.usage };
  } catch (e) {
    const blocked = e && e.code === 'LLM_GUARD_BLOCKED';
    // Same ledger-preserving contract runChatLoop now offers the app: a turn
    // that dies mid-loop still reports the work it had already done.
    const partial = (e && e.partial) || {};
    return { ok: false, blocked, durationMs: Date.now() - started, audit, events, security, blockedPayload,
             error: e && e.message, reply: '', toolTrace: partial.toolTrace || [], iterations: partial.iterations || 0 };
  }
}

function summarize(tag, r) {
  const tools = (r.toolTrace || []).map((t) => t.name);
  console.log(`  ${tag.padEnd(10)} ${r.blocked ? 'BLOCKED' : r.ok ? 'ok' : 'ERROR'}  ` +
    `${String(r.durationMs).padStart(6)}ms  iters=${r.iterations || 0}  tools=${tools.length}  ` +
    `reply=${(r.reply || '').length}ch  audit=${r.audit.length}`);
  if (r.audit.length) for (const a of r.audit) console.log(`             audit: ${a.operation} ${a.decision} ${a.durationMs}ms ${a.detail || ''}`);
  if (r.error) console.log(`             error: ${r.error}`);
  if (tools.length) console.log(`             tools: ${tools.join(', ')}`);
}

async function main() {
  const repo = openLiveDb();
  const { provider, key, model } = resolveProvider(repo);
  const guard = makeGuard();
  console.log(`provider=${provider.type}/${model}  guard=${guard.base_url}\n`);

  const mcp = require('../src/main/mcp/manager');
  let toolset = null;
  try {
    const built = await mcp.buildToolset(null);
    toolset = { tools: built.tools || [], call: (n, a) => mcp.callTool(n, a, built.routes) };
    console.log(`mcp: ${toolset.tools.length} tools available\n`);
  } catch (e) { console.log(`mcp: unavailable (${e.message}) — tool workloads will run tool-less\n`); }

  for (const workload of WORKLOADS) {
    console.log(`── ${workload.label} ──────────────────────────────`);
    const ts = workload.tools ? toolset : null;
    const off = await runOnce({ repo, provider, key, model, guard: null, workload, toolset: ts });
    summarize('guard-off', off);
    const on = await runOnce({ repo, provider, key, model, guard, workload, toolset: ts });
    summarize('guard-on', on);
    fs.writeFileSync(path.join(os.tmpdir(), `fw-${workload.id}.json`), JSON.stringify({ off, on }, null, 2));
    console.log('');
  }
  try { mcp.disposeAll(); } catch {}
}

app.whenReady().then(() => main().then(() => app.exit(0), (e) => { console.error(e); app.exit(1); }));
