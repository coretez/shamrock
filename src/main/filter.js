'use strict';

// Our own noise filter for tool results (RTK-inspired) — deterministic, no LLM.
//
// MCP tool output is the biggest token sink after skills (a 74k report, a 300-line
// `git log`, a giant JSON blob). This strips low-signal content BEFORE the result
// re-enters the model's context: ANSI codes, base64/data blobs, pretty-print
// whitespace, duplicate lines, absurdly long lines, and — as a backstop — the
// middle of anything still huge (keeping head AND tail, since summaries/verdicts
// usually live at the end). Every rule that fires is reported for the glass box.

const ANSI = /\x1b\[[0-9;]*m/g;
const DATA_URI = /data:[^;\s]+;base64,[A-Za-z0-9+/=]+/g;
const BASE64_BLOB = /[A-Za-z0-9+/]{300,}={0,2}/g;
const LONG_LINE = 2000;

// Epoch-millisecond timestamps, rendered as ISO 8601.
//
// Two reasons, one of them found the hard way. The soft one: a model reasons
// about "2026-08-14T10:28:00Z" and cannot reason about 1785304080000, so every
// timeline question over raw epochs is answered by guesswork.
//
// The hard one: a 13-digit epoch has roughly a 1-in-10 chance of passing the
// Luhn checksum, and Presidio's credit-card recognizer is exactly a 13-19 digit
// Luhn check. Fluency case records are full of epoch-millis, so an LLM firewall
// with a PII policy blocks SOC investigations at random — with a confidence of
// 1.0, on a credit-card rule, over a timestamp. No threshold can separate those;
// the fix is to stop putting bare epochs on the wire.
//
// The window is 2015-01-01 .. 2035-01-01, which keeps this from rewriting
// arbitrary 13-digit identifiers, and cannot collide with a 13-digit card
// number (those begin with 4, an order of magnitude above the range).
const EPOCH_MS = /\b(1[4-9]\d{11}|20[0-4]\d{10})\b/g;
const EPOCH_MS_MIN = Date.UTC(2015, 0, 1);
const EPOCH_MS_MAX = Date.UTC(2035, 0, 1);

/** An epoch-millis value as ISO 8601, or null if it is not one. */
function isoFromEpochMs(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < EPOCH_MS_MIN || n > EPOCH_MS_MAX) return null;
  const d = new Date(n);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

/** Every epoch-millis token inside a string, converted in place. */
function convertEpochsInText(text, hit) {
  return text.replace(EPOCH_MS, (m) => {
    const iso = isoFromEpochMs(m);
    if (!iso) return m;
    hit.n += 1;
    return iso;
  });
}

/**
 * Convert epoch-millis in a PARSED structure, so a number stays a JSON value
 * and becomes a quoted string rather than a bare token that breaks the parse.
 *
 * Strings are scanned rather than matched whole: MCP servers routinely return
 * a CSV or log blob as ONE JSON string field, and a whole-string test walks
 * straight past every timestamp inside it. That is exactly how a real Expo
 * monthly report still tripped the credit-card rule after the first fix.
 *
 * Returns the converted tree; `hit.n` counts conversions.
 */
function convertEpochsDeep(node, hit) {
  if (typeof node === 'number') { const iso = isoFromEpochMs(node); if (iso) { hit.n += 1; return iso; } return node; }
  if (typeof node === 'string') return convertEpochsInText(node, hit);
  if (Array.isArray(node)) return node.map((v) => convertEpochsDeep(v, hit));
  if (node && typeof node === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(node)) out[k] = convertEpochsDeep(v, hit);
    return out;
  }
  return node;
}

/**
 * @param {string} name  tool name (reserved for per-tool profiles later)
 * @param {string} text  raw tool result
 * @param {object} [opts] { cap = 24000 }
 * @returns {{text:string, before:number, after:number, rules:string[]}}
 */
function filterToolResult(name, text, opts = {}) {
  const cap = opts.cap || 24000;
  const rules = [];
  let out = String(text == null ? '' : text);
  const before = out.length;
  if (!out) return { text: out, before, after: 0, rules };

  // 1. ANSI colour codes
  if (ANSI.test(out)) { out = out.replace(ANSI, ''); rules.push('ansi'); }
  ANSI.lastIndex = 0;

  // 2. data: URIs and long base64 blobs → markers
  if (DATA_URI.test(out)) { out = out.replace(DATA_URI, '[data-uri elided]'); rules.push('data-uri'); }
  DATA_URI.lastIndex = 0;
  out = out.replace(BASE64_BLOB, (m) => { if (!rules.includes('base64')) rules.push('base64'); return `[base64 ${m.length}b elided]`; });

  // 3. JSON → minify (drop pretty-print whitespace losslessly), converting
  //    epoch-millis on the parsed tree so a timestamp that was a NUMBER comes
  //    back as a quoted string instead of a bare token that breaks the parse.
  const t = out.trim();
  let wasJson = false;
  if (t.startsWith('{') || t.startsWith('[')) {
    try {
      const hit = { n: 0 };
      const min = JSON.stringify(convertEpochsDeep(JSON.parse(t), hit));
      wasJson = true;
      if (hit.n) rules.push('epoch-iso');
      if (min.length < out.length || hit.n) { out = min; if (!rules.includes('json-min')) rules.push('json-min'); }
    } catch { /* not JSON */ }
  }

  // 4. Epoch-millis → ISO 8601 in free text (see EPOCH_MS above). JSON was
  //    already handled structurally above; running the text pass over it too
  //    would corrupt the quoting.
  if (!wasJson) {
    const hit = { n: 0 };
    out = convertEpochsInText(out, hit);
    if (hit.n && !rules.includes('epoch-iso')) rules.push('epoch-iso');
  }

  // 5. Trailing whitespace + collapse 3+ blank lines
  const ws = out.replace(/[ \t]+$/gm, '').replace(/\n{3,}/g, '\n\n');
  if (ws.length < out.length) { out = ws; rules.push('whitespace'); }

  // 6. Collapse consecutive duplicate lines
  {
    const lines = out.split('\n');
    const dedup = [];
    let run = 0;
    for (let i = 0; i < lines.length; i++) {
      if (i > 0 && lines[i] === lines[i - 1] && lines[i].trim()) { run++; continue; }
      if (run > 0) { dedup[dedup.length - 1] = `${lines[i - 1]}  (×${run + 1})`; run = 0; }
      dedup.push(lines[i]);
    }
    if (run > 0) dedup[dedup.length - 1] = `${lines[lines.length - 1]}  (×${run + 1})`;
    const joined = dedup.join('\n');
    if (joined.length < out.length) { out = joined; rules.push('dedup-lines'); }
  }

  // 7. Truncate absurdly long single lines
  {
    let hit = false;
    out = out.split('\n').map((l) => {
      if (l.length > LONG_LINE) { hit = true; return l.slice(0, LONG_LINE) + `…[+${l.length - LONG_LINE} chars]`; }
      return l;
    }).join('\n');
    if (hit) rules.push('long-line');
  }

  // 8. Backstop: still huge → keep head + tail, elide the middle
  if (out.length > cap) {
    const head = out.slice(0, Math.floor(cap * 0.7));
    const tail = out.slice(-Math.floor(cap * 0.2));
    out = head + `\n…[filtered: ${out.length - head.length - tail.length} chars elided from middle]…\n` + tail;
    rules.push('middle-elide');
  }

  return { text: out, before, after: out.length, rules };
}

module.exports = { filterToolResult };
