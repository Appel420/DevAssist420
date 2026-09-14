'use strict'
/**
 * Step 1 — Canonical State Loader (fail-closed)
 * Missing/malformed/invalid-hash/stale → DENY. Valid → ALLOW.
 * Integrity: SHA-256 over deterministic (key-sorted) JSON, excluding integrity_hash.
 */
const crypto = require('crypto')
const fs = require('fs')

const REQUIRED_FIELDS = ['runtimeMode', 'selectedModelId', 'maxTokens', 'createdAt', 'owner_id']
const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

function canonicalJson(obj) {
  return JSON.stringify(obj, Object.keys(obj).sort())
}

function computeStateHash(state) {
  const body = { ...state }
  delete body.integrity_hash
  return crypto.createHash('sha256').update(canonicalJson(body)).digest('hex')
}

function verifyState(state, opts = {}) {
  const maxAge = opts.maxAgeMs ?? MAX_AGE_MS
  if (!state || typeof state !== 'object') {
    return { ok: false, reason: 'malformed_state' }
  }
  for (const f of REQUIRED_FIELDS) {
    if (state[f] === undefined || state[f] === null) {
      return { ok: false, reason: `missing_field:${f}` }
    }
  }
  if (!['offline', 'hybrid', 'online'].includes(state.runtimeMode)) {
    return { ok: false, reason: 'invalid_runtime_mode' }
  }
  let created
  try {
    created = Date.parse(state.createdAt)
  } catch {
    return { ok: false, reason: 'stale_state' }
  }
  if (Number.isNaN(created) || Date.now() - created > maxAge || Date.now() - created < 0) {
    return { ok: false, reason: 'stale_state' }
  }
  const stored = state.integrity_hash
  if (!stored || typeof stored !== 'string') {
    return { ok: false, reason: 'missing_hash' }
  }
  const calc = computeStateHash(state)
  if (stored.toLowerCase() !== calc) {
    return { ok: false, reason: 'invalid_hash' }
  }
  return { ok: true, hash: calc }
}

function loadCanonicalState(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    throw new Error('FAIL_CLOSED: canonical state missing')
  }
  let parsed
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'))
  } catch {
    throw new Error('FAIL_CLOSED: canonical state malformed')
  }
  const result = verifyState(parsed)
  if (!result.ok) {
    throw new Error(`FAIL_CLOSED: ${result.reason}`)
  }
  return { state: parsed, hash: result.hash }
}

module.exports = { verifyState, computeStateHash, loadCanonicalState, REQUIRED_FIELDS }
