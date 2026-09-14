# Step 14 — Integration Wiring

**Status:** IN PROGRESS
**Linear:** SOV-9
**Branch:** `hardening/step-14-integration`
**Architecture anchor:** `3d344c09a44f9abe55135062ebd4669cfe8fe1e7`

## What this proves

Modules that pass individually can still be bypassed when wired together.
This step proves they cannot.

## Boot sequence

```
Canonical State (fail closed)
  → Identity
  → Authority
  → Policy
  → DevAssist420 Router
  → TaskEnvelope (immutable)
  → Inference Router
  → SCAR (every decision)
```

Independent path:

```
Public Feed → Normalizer → Local Cache → Market UI
```

## Negative tests (all must PASS)

| Test | Expected |
|------|----------|
| Missing state file | FAIL CLOSED |
| Malformed JSON | FAIL CLOSED |
| Invalid hash | FAIL CLOSED |
| Stale state | FAIL CLOSED |
| Bypass DevAssist420 | DENY |
| Bypass Identity/Policy | DENY |
| Mutate sealed TaskEnvelope | DENY |
| Provider quota | Local still available |
| Unauthorized fallback | DENY |
| Private data → Market Intel | DENY |
| Offline → network attempt | DENY |
| No SCAR evidence | GATE CLOSED |

## Files

- `backend/state/canonical_state.js` — fail-closed loader (replaces soft-default `state-store.js`)
- `backend/integration/boot.js` — single orchestration entry point
- `tests/test_integration_matrix.js` — negative tests first
