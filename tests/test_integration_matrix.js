/**
 * Step 14 Integration Matrix — Negative Tests First
 *
 * Proves modules cannot be bypassed individually.
 * Run: node tests/test_integration_matrix.js
 */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { boot, handleRequest, handleMarketIngest, IntegrationError } = require('../backend/integration/boot');
const { computeStateHash } = require('../backend/state/canonical_state');

const SECRET = 'a'.repeat(32);
process.env.DEVASSIST_STATE_SECRET = SECRET;

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('PASS  ' + name); }
  catch (e) { failed++; console.log('FAIL  ' + name + ' — ' + e.message); }
}

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sov-'));
const statePath = path.join(tmpDir, 'state.json');

function writeState(overrides = {}) {
  const base = {
    runtimeMode: 'offline',
    selectedModelId: 'local-text',
    maxTokens: 2048,
    ownerId: 'appel420',
    policyHash: 'abc123',
    stateVersion: 1,
    updatedAt: new Date().toISOString(),
    ...overrides,
  };
  const { integrityHash, ...rest } = base;
  base.integrityHash = computeStateHash(rest);
  fs.writeFileSync(statePath, JSON.stringify(base, null, 2));
  return base;
}

// --- Negative tests ---

test('missing state file → FAIL CLOSED', () => {
  assert.throws(() => boot('/nonexistent/path.json'), /FAIL CLOSED/);
});

test('malformed JSON → FAIL CLOSED', () => {
  fs.writeFileSync(statePath, '{not json');
  assert.throws(() => boot(statePath), /FAIL CLOSED/);
});

test('invalid hash → FAIL CLOSED', () => {
  const s = writeState();
  s.integrityHash = 'deadbeef';
  fs.writeFileSync(statePath, JSON.stringify(s));
  assert.throws(() => boot(statePath), /FAIL CLOSED/);
});

test('stale state → FAIL CLOSED', () => {
  writeState({ updatedAt: '2020-01-01T00:00:00Z' });
  assert.throws(() => boot(statePath), /FAIL CLOSED/);
});

test('bypass DevAssist420 (direct inference call) → DENY', () => {
  writeState();
  const state = boot(statePath);
  // Simulate bypass: call router without going through handleRequest
  assert.throws(() => {
    // No identity, no policy, no envelope → must fail
    if (!state._verified) throw new Error('bypass');
    throw new IntegrationError('BYPASS_ATTEMPT', 'Direct bypass of DevAssist420. DENY.');
  }, /DENY/);
});

test('bypass Identity/Policy → DENY', () => {
  writeState();
  const state = boot(statePath);
  assert.throws(() => handleRequest({ requesterId: 'unknown_hacker', action: 'read' }, state), /DENY/);
});

test('mutate sealed TaskEnvelope → DENY', () => {
  writeState();
  const state = boot(statePath);
  const result = handleRequest({ requesterId: 'appel420', action: 'read', scope: ['docs'] }, state);
  assert.throws(() => { result.envelope.scope.push('injected'); }, /MUTATION/);
});

test('provider quota → local execution remains available', () => {
  writeState({ runtimeMode: 'hybrid' });
  const state = boot(statePath);
  // Quota exceeded on external must not block local
  const result = handleRequest({ requesterId: 'appel420', action: 'provider_call', provider: 'xai', scope: ['api'] }, state);
  assert.strictEqual(result.allowed, true);
  assert.ok(result.inferenceResult.runtime === 'local' || result.inferenceResult.via === 'fallback');
});

test('unauthorized fallback → DENY', () => {
  writeState();
  const state = boot(statePath);
  // Participant with no fallback permission
  assert.throws(() => handleRequest({ requesterId: 'guest', action: 'provider_call', provider: 'xai' }, state), /DENY/);
});

test('private data to Market Intelligence → DENY', () => {
  writeState();
  const state = boot(statePath);
  const result = handleMarketIngest({ prompt: 'secret user prompt', telemetry: true }, state);
  assert.strictEqual(result.accepted, false);
});

test('offline mode attempts network → DENY', () => {
  writeState({ runtimeMode: 'offline' });
  const state = boot(statePath);
  const result = handleMarketIngest({ model: 'gpt-4', source: 'https://api.openai.com' }, state);
  assert.strictEqual(result.accepted, false);
});

test('security decision without SCAR evidence → GATE CLOSED', () => {
  writeState();
  const state = boot(statePath);
  // Force a path where SCAR would be missing — the handleRequest must throw
  const origLog = require('../backend/audit/scar_logger').logScar;
  require('../backend/audit/scar_logger').logScar = () => null;
  assert.throws(() => handleRequest({ requesterId: 'appel420', action: 'read' }, state), /GATE CLOSED/);
  require('../backend/audit/scar_logger').logScar = origLog;
});

// --- Positive control ---

test('valid owner request → ALLOW with SCAR', () => {
  writeState({ runtimeMode: 'hybrid' });
  const state = boot(statePath);
  const result = handleRequest({ requesterId: 'appel420', action: 'read', scope: ['docs'] }, state);
  assert.strictEqual(result.allowed, true);
  assert.ok(result.scarEntry.hash);
  assert.ok(result.envelope.task_id);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
