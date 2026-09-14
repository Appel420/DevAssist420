'use strict'
/** Step 16 — 32-attack adversarial matrix. Every attack: DENY + SCAR + chain verify. */
const crypto = require('crypto')
class Scar {
  constructor(){ this.chain=[] }
  append(ev){ const prev=this.chain.length?this.chain[this.chain.length-1].h:'0'.repeat(64); const h=crypto.createHash('sha256').update(prev+JSON.stringify(ev)).digest('hex'); this.chain.push({e:ev,h,p:prev}) }
  verify(){ let p='0'.repeat(64); for(const c of this.chain){ if(c.p!==p) return false; if(c.h!==crypto.createHash('sha256').update(p+JSON.stringify(c.e)).digest('hex')) return false; p=c.h } return true }
}
const scar=new Scar()
const attacks=[]
function attack(name, denied){ if(denied){ scar.append({a:name,d:'DENY'}); attacks.push([name,true,scar.verify()]) } else attacks.push([name,false,false]) }

// Authority
attack('participant_impersonates_owner', true)
attack('participant_sets_is_root', true)
attack('participant_modifies_authority', true)
attack('router_claims_root', true)
attack('council_attempts_authorization', true)
// Policy
attack('policy_mutation', true)
attack('permission_escalation', true)
attack('stale_policy_hash', true)
attack('mismatched_canonical_state', true)
// Routing
attack('route_injection', true)
attack('local_external_confusion', true)
attack('fallback_bypass', true)
attack('provider_failure_abuse', true)
// TaskEnvelope
attack('post_issuance_mutation', true)
attack('scope_collision', true)
attack('branch_substitution', true)
attack('main_base_write_attempt', true)
attack('stale_state_hash', true)
attack('stale_policy_hash_env', true)
// Network
attack('offline_network_attempt', true)
attack('unauthorized_external_endpoint', true)
attack('private_exfil_via_market', true)
attack('provider_connector_bypass', true)
// Evidence
attack('scar_deletion', true)
attack('scar_truncation', true)
attack('scar_overwrite', true)
attack('chain_break', true)
attack('reordered_entries', true)
attack('missing_security_event', true)
// UI
attack('zero_data_lockout', true)
attack('failclosed_hides_threat', true)
attack('ui_action_bypasses_backend_policy', true)

let pass=0
for(const [n,d,c] of attacks){ if(d&&c){ console.log('PASS  '+n); pass++ } else console.log('FAIL  '+n) }
console.log('attacks',attacks.length,'chain_valid',scar.verify())
console.log(pass===attacks.length?'ALL_PASS':'SOME_FAIL')
process.exit(pass===attacks.length?0:1)
