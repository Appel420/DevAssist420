# Hardening Steps 14 – 16

**Status:** PASS / GATES OPEN  
**Date:** 2026-09-14  
**Architecture anchor:** `3d344c09a44f9abe55135062ebd4669cfe8fe1e7`  
**Branch:** `hardening/steps-14-16`

## Step 14 — Integration Wiring
Proves the 13 modules cannot be bypassed individually.
- 9/9 integration tests PASS (after escalation-path fix)
- Unauthorized fallback returns DENY cleanly
- Provider quota cannot touch local execution
- No evidence → gate closed

## Step 15 — Real TPM / Production Attestation
- Empty/fake TPM → unconditional DENY
- Real TPM builds COSE_Sign1 (tag 18, alg -50 = ML-DSA-87, RFC 9964)
- Deterministic CBOR, nonce-bound, replay-protected
- 5/5 tests PASS
- *Physical TPM hardware not yet live on this host*

## Step 16 — Adversarial Hardening
- 32 attacks, all DENY + SCAR + chain verify
- SCAR: 32 entries, chain_valid=True, no delete/truncate/overwrite API
- Invariants 14–16 enforced as cross-cutting gates

## Invariants 14 – 16 (cross-cutting)
14. UI zero-data never hides the shell  
15. No Google Fonts, no unnecessary CDN  
16. Missing/unverifiable canonical state → FAIL CLOSED  

All three enforced. Step 16 was the live gap on `main` (`state-store.js` soft-defaulted); fixed in `canonical_state.js`.
