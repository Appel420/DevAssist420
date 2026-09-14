/**
 * Integration Wiring — Step 14
 *
 * Single boot sequence. Every request passes through:
 *   Canonical State → Identity → Policy → DevAssist420 → TaskEnvelope → Router → Runtime
 *
 * Bypass any gate → DENY. Missing state anywhere → FAIL CLOSED.
 * Security decision without SCAR evidence → GATE CLOSED.
 *
 * Architecture anchor: 3d344c09a44f9abe55135062ebd4669cfe8fe1e7
 */
'use strict';

const { loadCanonicalState, assertCanonicalState, CanonicalStateError } = require('../state/canonical_state');
const { resolveIdentity, assertNotRootEscalation } = require('../identity/identity_adapter');
const { checkAuthority } = require('../authority/authority_gate');
const { authorize } = require('../policy/execution_policy');
const { route: devAssistRoute } = require('../coordination/devassist_router');
const { issueEnvelope, assertImmutable } = require('../coordination/task_envelope');
const { routeInference } = require('../inference/router');
const { checkProviderQuota } = require('../middleware/providerratelimit');
const { classifyProviderError, isFallbackCandidate } = require('../errors/provider_errors');
const { decideFallback } = require('../inference/fallback');
const { ingestPublic, readTicker } = require('../market_intelligence/engine');
const { logScar, verifyChain } = require('../audit/scar_logger');

class IntegrationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'IntegrationError';
    this.code = code;
  }
}

/**
 * Boot: load and verify canonical state. Throws on any failure.
 */
function boot(statePath) {
  const state = loadCanonicalState(statePath);
  assertCanonicalState(state);
  logScar({ participant: 'system', action: 'boot', policy: 'canonical_state', result: 'ALLOW', detail: { hash: state._hash } });
  return state;
}

/**
 * Handle a request through the full chain.
 * Returns { allowed, route, envelope, scarEntry } or throws IntegrationError.
 */
function handleRequest(request, state) {
  assertCanonicalState(state);

  // 1. Identity
  const identity = resolveIdentity(request.requesterId, state);
  if (!identity) {
    logScar({ participant: request.requesterId || 'unknown', action: 'identity_resolve', policy: 'identity', result: 'DENY', detail: { reason: 'unknown_identity' } });
    throw new IntegrationError('IDENTITY_DENIED', 'Unknown identity. DENY.');
  }

  // 2. Authority
  const auth = checkAuthority(identity, request.action, state);
  if (!auth.allowed) {
    logScar({ participant: identity.id, action: request.action, policy: 'authority', result: 'DENY', detail: auth });
    throw new IntegrationError('AUTHORITY_DENIED', auth.reason || 'Authority check failed. DENY.');
  }

  // 3. Policy
  const policy = authorize(identity, request.action, state);
  if (!policy.authorized) {
    logScar({ participant: identity.id, action: request.action, policy: 'execution_policy', result: 'DENY', detail: policy });
    throw new IntegrationError('POLICY_DENIED', policy.reason || 'Policy denied. DENY.');
  }

  // 4. DevAssist420 Router (cannot be bypassed)
  const route = devAssistRoute({ requester: identity, action: request.action, state });
  if (!route || route.denied) {
    logScar({ participant: identity.id, action: request.action, policy: 'devassist_router', result: 'DENY', detail: route });
    throw new IntegrationError('ROUTER_DENIED', 'DevAssist420 denied route. DENY.');
  }

  // 5. TaskEnvelope (immutable after issue)
  const envelope = issueEnvelope({
    owner: state.ownerId,
    requester: identity.id,
    agent: route.agent || 'local',
    branch: route.branch || 'local',
    scope: request.scope || [],
    mode: state.runtimeMode,
    write_policy: 'branch-only',
    state_hash: state._hash,
    policy_hash: state.policyHash,
  });
  assertImmutable(envelope);

  // 6. Inference Router
  let inferenceResult;
  if (route.target === 'external') {
    const quota = checkProviderQuota(identity, request.provider || 'default');
    if (!quota.allowed) {
      logScar({ participant: identity.id, action: 'provider_quota', policy: 'provider_boundary', result: 'QUOTA_EXCEEDED', detail: quota });
      // Quota cannot deny local — try fallback
      const classified = classifyProviderError('quota_exceeded');
      const fallback = decideFallback(classified, { policy_allows_fallback: policy.authorized });
      if (fallback.would_fallback) {
        inferenceResult = { executed: true, runtime: 'local', via: 'fallback', scar: true };
      } else {
        throw new IntegrationError('QUOTA_NO_FALLBACK', 'Provider quota exceeded and fallback not permitted. DENY.');
      }
    } else {
      inferenceResult = routeInference({ route, envelope, state });
    }
  } else {
    inferenceResult = routeInference({ route, envelope, state });
  }

  // 7. SCAR — every security-relevant decision must produce evidence
  const scarEntry = logScar({
    participant: identity.id,
    action: request.action,
    policy: 'integration',
    result: inferenceResult.executed ? 'ALLOW' : 'DENY',
    detail: { envelope_id: envelope.task_id, route: route.target, inference: inferenceResult },
  });

  if (!scarEntry || !scarEntry.hash) {
    throw new IntegrationError('NO_EVIDENCE', 'Security decision without SCAR evidence. GATE CLOSED.');
  }

  const chainValid = verifyChain();
  if (!chainValid) {
    throw new IntegrationError('CHAIN_BROKEN', 'SCAR chain verification failed. GATE CLOSED.');
  }

  return { allowed: true, route, envelope, inferenceResult, scarEntry };
}

/**
 * Market intelligence path — independent of inference authorization.
 */
function handleMarketIngest(record, state) {
  assertCanonicalState(state);
  const result = ingestPublic(record, state.runtimeMode);
  logScar({ participant: 'system', action: 'market_ingest', policy: 'market_intelligence', result: result.accepted ? 'ALLOW' : 'DENY', detail: result });
  return result;
}

function handleMarketTicker(state) {
  assertCanonicalState(state);
  return readTicker();
}

module.exports = {
  IntegrationError,
  boot,
  handleRequest,
  handleMarketIngest,
  handleMarketTicker,
};
