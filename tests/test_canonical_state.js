'use strict'
const { verifyState, computeStateHash } = require('../backend/state/canonical_state')

function assert(cond, msg) { if (!cond) throw new Error('FAIL: ' + msg) }

const base = {
  runtimeMode: 'offline',
  selectedModelId: 'local-text',
  maxTokens: 2048,
  createdAt: new Date().toISOString(),
  owner_id: 'Appel420',
}
base.integrity_hash = computeStateHash(base)

const cases = [
  ['missing_state', () => verifyState(null).ok === false],
  ['malformed', () => verifyState('x').ok === false],
  ['missing_hash_field', () => { const s={...base}; delete s.integrity_hash; return verifyState(s).reason === 'missing_hash' }],
  ['invalid_hash', () => { const s={...base, integrity_hash:'00'.repeat(32)}; return verifyState(s).reason === 'invalid_hash' }],
  ['tampered_field', () => { const s={...base}; s.maxTokens=999; return verifyState(s).ok === false }],
  ['stale_state', () => { const s={...base, createdAt:'2020-01-01T00:00:00Z', integrity_hash:computeStateHash({...base,createdAt:'2020-01-01T00:00:00Z'})}; return verifyState(s).reason === 'stale_state' }],
  ['valid_state', () => verifyState(base).ok === true],
  ['hash_matches', () => verifyState(base).hash === computeStateHash(base)],
]

let pass = 0
for (const [name, fn] of cases) {
  try { assert(fn(), name); console.log('PASS  ' + name); pass++ }
  catch (e) { console.log('FAIL  ' + name + '  ' + e.message) }
}
console.log(pass === cases.length ? 'ALL_PASS' : 'SOME_FAIL ' + pass + '/' + cases.length)
process.exit(pass === cases.length ? 0 : 1)
