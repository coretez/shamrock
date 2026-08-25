'use strict';

const { PROVIDERS, registryList } = require('./registry');
const { openaiCompat } = require('./openai-compat');
const { anthropic } = require('./anthropic');

/**
 * Build a connector for a resolved connection.
 * @param {{type:string, base_url?:string, baseUrl?:string}} conn
 * @param {string} key  decrypted secret (main process only)
 */
function getConnector(conn, key, { guard = null, guardKey = null, onAudit = null } = {}) {
  const type = conn.type;
  const def = PROVIDERS[type];
  if (!def) throw new Error(`Unknown provider type: ${type}`);
  // Guards are wire-protocol adapters, not vendor allowlists. Trylon speaks
  // two protocols — an OpenAI-compatible /v1 route and a distinct /anthropic
  // route — and forwards the request body verbatim to whatever upstream the
  // gateway operator configured. So the gate is the connection's STYLE, which
  // is what actually has to match; gating on `type` locked out Qwen, Kimi and
  // Gemini, which are all OpenAI-compatible and route fine.
  if (guard && guard.enabled && !['openai', 'anthropic'].includes(def.style)) {
    throw new Error(`${guard.label || 'The enabled LLM guard'} cannot route ${def.label || type}: no matching wire protocol. Disable the guard or select another connection.`);
  }
  if (guard && guard.enabled && guard.kind !== 'trylon' && def.style !== 'openai') {
    throw new Error('The enabled LLM guard supports OpenAI-compatible connections only. Disable the guard or select an OpenAI-compatible model connection.');
  }
  let baseUrl = conn.base_url || conn.baseUrl || def.baseUrl;
  if (guard && guard.enabled) {
    baseUrl = guard.base_url;
    if (guard.kind === 'trylon' && type === 'anthropic') baseUrl = `${String(baseUrl).replace(/\/v1\/?$/i, '').replace(/\/+$/, '')}/anthropic`;
  }
  const effectiveKey = guard && guard.enabled && guard.kind !== 'trylon' && guard.auth_mode === 'bearer' ? guardKey : key;
  const connector = def.style === 'anthropic'
    ? anthropic({ baseUrl, key: effectiveKey })
    : openaiCompat({ baseUrl, key: effectiveKey });
  if (!guard || !guard.enabled || typeof onAudit !== 'function') return connector;

  const audited = async (operation, fn, model = null) => {
    const started = Date.now();
    try {
      const result = await fn();
      const meta = result && result.guardMeta;
      const blocked = !!(result && result.finishReason === 'content_filter') || !!(meta && meta.blocked);
      // WHICH SIDE was refused is the whole point of the firewall card: an
      // outbound block means the prompt never left the machine, an inbound
      // block means the model already saw it. Trylon does not label the
      // direction, but it leaks it in the response id — a block on the way IN
      // has no upstream response to copy an id from, so it synthesizes
      // `trylon-blocked-<epoch>`; a block on the way OUT carries the real
      // upstream id through (see proxy_utils._create_openai_blocked_response_body).
      // This keyed on `type === 'openai'`, so every other OpenAI-compatible
      // vendor reported direction=unknown and got the generic 'guard' stage.
      const trylonId = result && result.raw && typeof result.raw.id === 'string' ? result.raw.id : '';
      const direction = !blocked ? null : meta && meta.stage
        ? (meta.stage === 'input' ? 'outbound' : meta.stage === 'output' ? 'inbound' : 'unknown')
        : guard.kind === 'trylon' && def.style === 'openai'
          ? (trylonId.startsWith('trylon-blocked-') ? 'outbound' : 'inbound')
          : 'unknown';
      const detail = [
        direction ? `direction=${direction}` : null,
        result && result.finishReason ? `finish_reason=${result.finishReason}` : null,
        meta && meta.safetyCode ? `safety_code=${meta.safetyCode}` : null,
        meta && meta.action ? `action=${meta.action}` : null,
        meta && meta.requestId ? `request_id=${meta.requestId}` : null,
        blocked && meta && meta.message ? meta.message : null
      ].filter(Boolean).join(' · ') || null;
      const auditId = onAudit({ operation, model, decision: blocked ? 'blocked' : 'allowed', durationMs: Date.now() - started, detail });
      if (blocked && result) {
        result.security = {
          blocked: true,
          direction,
          stage: direction === 'outbound' ? 'llm_firewall' : direction === 'inbound' ? 'gate_guard' : 'guard',
          decision: 'blocked',
          message: (meta && meta.message) || result.text || 'Model traffic was blocked by the configured guard.',
          safetyCode: meta && meta.safetyCode ? String(meta.safetyCode) : null,
          action: meta && meta.action ? String(meta.action) : null,
          requestId: meta && meta.requestId ? String(meta.requestId) : null,
          auditId: Number(auditId) || null,
          guardLabel: guard.label || 'LLM guard'
        };
      }
      return result;
    } catch (error) {
      const detail = error && error.status ? `HTTP ${error.status}` : (error && error.code ? String(error.code) : 'guard call failed');
      onAudit({ operation, model, decision: 'error', durationMs: Date.now() - started, detail });
      throw error;
    }
  };
  return {
    listModels: () => audited('models', () => connector.listModels()),
    chat: (input) => audited('chat', async () => {
      // Trylon's OpenAI proxy currently supports non-streaming completions.
      // Preserve Shamrock's streaming contract by emitting the completed text
      // as one final delta after the guard has accepted it.
      if (guard.kind === 'trylon' && input && typeof input.onDelta === 'function') {
        const onDelta = input.onDelta;
        const result = await connector.chat({ ...input, onDelta: undefined });
        if (result && result.text && result.finishReason !== 'content_filter' && !(result.guardMeta && result.guardMeta.blocked)) onDelta({ text: result.text });
        return result;
      }
      return connector.chat(input);
    }, input && input.model)
  };
}

/**
 * Verify a connection works. Tries a live model list; if the provider doesn't
 * expose /models, falls back to a 1-token chat ping against `probeModel`.
 * @returns {Promise<{ok:boolean, models?:string[], error?:string}>}
 */
async function testConnection(conn, key, probeModel) {
  const connector = getConnector(conn, key);
  try {
    const models = await connector.listModels();
    if (models.length) return { ok: true, models };
  } catch (modelsErr) {
    const model = probeModel || conn.default_model || PROVIDERS[conn.type]?.fallbackModels?.[0];
    if (model) {
      try {
        await connector.chat({ model, messages: [{ role: 'user', content: 'ping' }], maxTokens: 1 });
        return { ok: true, models: [] };
      } catch (chatErr) {
        return { ok: false, error: chatErr.message };
      }
    }
    return { ok: false, error: modelsErr.message };
  }
  return { ok: true, models: [] };
}

module.exports = { getConnector, testConnection, registryList, PROVIDERS };
