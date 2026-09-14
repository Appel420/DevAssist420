'use strict'
const { TPMBridge, verifyTpmQuote, issueAttestation, cborEncode } = require('../backend/pqc/attestation')
const crypto = require('crypto')

function assert(c, m){ if(!c) throw new Error('FAIL: '+m) }
const ak = Buffer.from('AKPUBREAL')
const nonce = crypto.randomBytes(32)
const cases = []

cases.push(['empty_tpm_deny', () => { const r = issueAttestation('N1', new TPMBridge({hardwarePresent:false}), nonce); return r.valid===false && r.reason==='empty_or_fake_tpm' }])
cases.push(['real_tpm_cose_shape', () => { const r = issueAttestation('N1', new TPMBridge({hardwarePresent:true, akPub:ak}), nonce); return r.valid===true && r.cose.tag===18 && r.cose.protected.alg===-50 }])
cases.push(['nonce_mismatch_deny', () => { const q = new TPMBridge({hardwarePresent:true, akPub:ak}).quote(nonce); return verifyTpmQuote(q, Buffer.alloc(32,0), ak).ok===false }])
cases.push(['deterministic_cbor', () => { const a=cborEncode({b:2,a:1}); const b=cborEncode({a:1,b:2}); return a.equals(b) }])
cases.push(['stale_replay_deny', () => { const q=new TPMBridge({hardwarePresent:true, akPub:ak}).quote(nonce); q.attest.clock=Math.floor(Date.now()/1000)-9999; return verifyTpmQuote(q,nonce,ak).ok===false }])

let pass=0
for (const [n,f] of cases){ try{ assert(f(),n); console.log('PASS  '+n); pass++ }catch(e){ console.log('FAIL  '+n+'  '+e.message) } }
console.log(pass===cases.length?'ALL_PASS':'SOME_FAIL')
process.exit(pass===cases.length?0:1)
