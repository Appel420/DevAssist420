/**
 * Canonical State Loader — Step 1 / Invariant 16
 *
 * FAIL CLOSED: missing, malformed, invalid-hash, or stale state → throw.
 * No defaultState() fallback. No hardcoded secret.
 *
 * Architecture anchor: 3d344c09a44f9abe55135062ebd4669cfe8fe1e7
 */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const REQUIRED_FIELDS = ['runtimeMode', 'selectedModelId', 'maxTokens', 'ownerId', 'policyHash', 'stateVersion'];
const VALID_MODES = ['offline', 'hybrid', 'online'];
const MAX_STATE_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

class CanonicalStateError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'CanonicalStateError';
    this.code = code;
    this.failClosed = true;
  }
}

function computeStateHash(state) {
  const canonical = JSON.stringify(state, Object.keys(state).sort());
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

function loadCanonicalState(filePath, options = {}) {
  const secret = process.env.DEVASSIST_STATE_SECRET;
  if (!secret || secret.length < 32) {
    throw new CanonicalStateError('MISSING_SECRET', 'DEVASSIST_STATE_SECRET must be set (min 32 chars). No hardcoded fallback.');
  }

  if (!filePath || !fs.existsSync(filePath)) {
    throw new CanonicalStateError('MISSING_STATE', `Canonical state file not found: ${filePath || '(none)'}. FAIL CLOSED.`);
  }

  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    throw new CanonicalStateError('READ_ERROR', `Cannot read state file: ${err.message}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new CanonicalStateError('MALFORMED_JSON', 'State file is not valid JSON. FAIL CLOSED.');
  }

  for (const field of REQUIRED_FIELDS) {
    if (parsed[field] === undefined || parsed[field] === null) {
      throw new CanonicalStateError('MISSING_FIELD', `Required field missing: ${field}. FAIL CLOSED.`);
    }
  }

  if (!VALID_MODES.includes(parsed.runtimeMode)) {
    throw new CanonicalStateError('INVALID_MODE', `Invalid runtimeMode: ${parsed.runtimeMode}`);
  }

  if (typeof parsed.maxTokens !== 'number' || parsed.maxTokens < 1) {
    throw new CanonicalStateError('INVALID_FIELD', 'maxTokens must be a positive number.');
  }

  // Integrity: recompute hash over all fields except integrityHash itself
  const { integrityHash, ...rest } = parsed;
  const expected = computeStateHash(rest);
  if (!integrityHash || integrityHash !== expected) {
    throw new CanonicalStateError('INVALID_HASH', 'State integrity hash mismatch or missing. FAIL CLOSED.');
  }

  // Freshness
  if (parsed.updatedAt) {
    const age = Date.now() - new Date(parsed.updatedAt).getTime();
    if (age > MAX_STATE_AGE_MS) {
      throw new CanonicalStateError('STALE_STATE', `State is stale (age ${Math.round(age / 86400000)}d). FAIL CLOSED.`);
    }
  }

  return Object.freeze({
    ...parsed,
    _verified: true,
    _hash: expected,
    _loadedAt: new Date().toISOString(),
  });
}

function assertCanonicalState(state) {
  if (!state || state._verified !== true) {
    throw new CanonicalStateError('UNVERIFIED', 'Canonical state not verified. FAIL CLOSED.');
  }
  return state;
}

module.exports = {
  CanonicalStateError,
  computeStateHash,
  loadCanonicalState,
  assertCanonicalState,
  REQUIRED_FIELDS,
};
