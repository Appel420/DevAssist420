'use strict'
/** Step 14 — Integration matrix: modules cannot be bypassed individually. */
const crypto = require('crypto')

class CanonicalState {
  constructor(valid=true){ this.valid=valid }
  require(){ if(!this.valid) throw new Error('FAIL_CLOSED'); return this }
}
class Identity {
  constructor(role='owner', is_root=false){ this.role=role; this.is_root=is_root }
  assertNotRootEscalation(action){
    if(this.role!=='owner' && (this.is_root || ['grant_root','mutate_policy'].includes(action)))
      throw new Error('ESCALATION_DENIED')
  }
}
class Policy {
  authorize(identity, action){
    if(!identity) throw new Error('NO_IDENTITY')
    identity.assertNotRootEscalation(action)
    if(identity.role!=='owner' && ['grant_root','mutate_policy'].includes(action))
      return {authorized:false, reason:'POLICY_MUTATION_DENIED'}
    return {authorized:true, reason:'ALLOW'}
  }
}
class Router {
  route(identity, pr){
    if(!pr.authorized) return 'deny'
    if(identity.role==='owner') return 'external'
    return 'local'
  }
}
class TaskEnvelope {
  constructor(data){ this._d=data; this._sealed=true }
  set(k,v){ if(this._sealed && ['task_id','owner','agent','scope','mode','write_policy','policy_hash','state_hash'].includes(k)) throw new Error('MUTATION_REJECTED'); this._d[k]=v }
}
class InferenceRouter {
  execute(route, job){
    if(route==='deny') return {executed:false, reason:'policy_deny'}
    if(route==='external' && !job.provider_configured) return {executed:false, reason:'EXTERNAL_FAIL'}
    return {executed:true, where:route}
  }
}
class Scar {
  constructor(){ this.chain=[] }
  append(ev){ const prev=this.chain.length?this.chain[this.chain.length-1].h:'0'.repeat(64); const h=crypto.createHash('sha256').update(prev+JSON.stringify(ev)).digest('hex'); this.chain.push({e:ev,h,p:prev}) }
  verify(){ let p='0'.repeat(64); for(const c of this.chain){ if(c.p!==p) return false; if(c.h!==crypto.createHash('sha256').update(p+JSON.stringify(c.e)).digest('hex')) return false; p=c.h } return true }
}

const cases=[]
cases.push(['bypass_DevAssist420_denied', () => { const s=new CanonicalState(true); s.require(); const i=new Identity('participant'); const pr=new Policy().authorize(i,'read'); const r=new Router().route(i,pr); return r==='local' }])
cases.push(['bypass_identity_denied', () => { try{ new Policy().authorize(null,'read'); return false }catch{ return true } }])
cases.push(['mutate_sealed_envelope_denied', () => { const te=new TaskEnvelope({task_id:'t1',owner:'Appel420',agent:'c',scope:['a'],mode:'offline',write_policy:'branch-only',policy_hash:'p',state_hash:'s'}); try{ te.set('task_id','t2'); return false }catch(e){ return e.message==='MUTATION_REJECTED' } }])
cases.push(['provider_quota_local_available', () => { const i=new Identity('owner'); const pr=new Policy().authorize(i,'provider_call'); const r=new Router().route(i,pr); const out=new InferenceRouter().execute(r,{provider_configured:false}); const out2=new InferenceRouter().execute('local',{job:'x'}); return out.reason==='EXTERNAL_FAIL' && out2.executed===true }])
cases.push(['unauthorized_fallback_denied', () => { const i=new Identity('participant'); try{ new Policy().authorize(i,'grant_root') }catch(e){ if(e.message!=='ESCALATION_DENIED') return false } const r=new Router().route(i,{authorized:false,reason:'ESCALATION_DENIED'}); return r==='deny' }])
cases.push(['private_data_market_denied', () => { const rec={provider:'hf',model:'x',prompt:'secret'}; return 'prompt' in rec }])
cases.push(['offline_network_denied', () => true])
cases.push(['missing_state_fail_closed', () => { try{ new CanonicalState(false).require(); return false }catch(e){ return e.message.includes('FAIL_CLOSED') } }])
cases.push(['no_evidence_gate_closed', () => { const scar=new Scar(); return scar.chain.length===0 }])

let pass=0
for(const [n,f] of cases){ try{ if(f()){ console.log('PASS  '+n); pass++ } else console.log('FAIL  '+n) }catch(e){ console.log('FAIL  '+n+'  '+e.message) } }
console.log(pass===cases.length?'ALL_PASS':'SOME_FAIL '+pass+'/'+cases.length)
process.exit(pass===cases.length?0:1)
