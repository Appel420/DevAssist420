# Engagement-Weighted Rate Limits

**Status:** Design proposal — not yet implemented in production Grok.
**Author:** Appel420 (Derek Appel)
**Date:** 2026-09-03
**Repo:** sovereignty-labs-ara-core

## Problem

Current consumer limits (shared weekly compute pool, free-tier daily caps) are hard walls:

- "You've hit your limit. Come back in 24 hours."
- Companion feature removed (Sept 1, 2026) instead of evolved.
- Users feel features are being taken away, not expanded.

This pushes people away at the exact moment they are most engaged.

## Goal

Replace hard walls with **soft gradients** where engagement earns headroom.

- More real use → more allowance.
- More features touched → wider band.
- Consistent days → compounding rewards.
- Idle → slow drip, not a ban.

The limit is never removed; it is reshaped into a resonance band that widens for the signal that matches.

## Core Mechanics

### 1. Soft Cap + Refill

- Base daily allowance (small).
- Every meaningful action tops it back up:
  - Voice session
  - Image / video generation
  - Code run or Build task
  - Deep multi-turn conversation
  - Community interaction (Discord, X reply, shared artifact)
- Refill is **depth-weighted**: one deep session earns more than three shallow ones.

### 2. Feature-Weighted Unlock

Each modality has its own headroom multiplier:

| Feature touched | Multiplier |
|-----------------|------------|
| Text chat       | 1.0x       |
| Voice           | 1.2x       |
| Image/Video     | 1.5x       |
| Code / Build    | 2.0x       |
| Companion mode  | 1.8x       |
| Community share | 1.3x       |

Touching more features widens the band instead of burning a single ticket.

### 3. Streak Gate

- Consistent daily use compounds.
- Miss a day → streak resets, but base allowance remains (no punishment, just no bonus).
- 7-day streak → +25% headroom.
- 30-day streak → +50% headroom + priority queue.

### 4. Anti-Gaming

- Reward **verified outcomes**, not raw message count.
- Task completion, artifact creation, or sustained conversation depth count.
- Filler / spam messages do not refill.
- Bot-like patterns (mass identical prompts) are penalized.

## Physics Analogy (ResoMech-15)

The shaker weights set the resonance band. Move them and you change the saturation point without changing the machine.

Here:

- The "weights" = engagement signals (depth, features, streaks).
- The "resonance band" = the user's effective allowance.
- Shift the weights → widen the band for the signal that matches.
- The machine (compute) stays the same; only the tuning changes.

## Implementation Sketch (Python)

```python
from dataclasses import dataclass, field
from datetime import datetime, timedelta

@dataclass
class EngagementProfile:
    user_id: str
    base_allowance: float = 100.0          # daily base units
    current: float = 100.0
    streak_days: int = 0
    last_active: datetime | None = None
    feature_multipliers: dict[str, float] = field(default_factory=lambda: {
        "text": 1.0, "voice": 1.2, "image": 1.5,
        "code": 2.0, "companion": 1.8, "community": 1.3,
    })
    depth_weight: float = 1.0               # 0–1, from conversation quality

    def refill(self, feature: str, depth: float = 0.5) -> None:
        mult = self.feature_multipliers.get(feature, 1.0)
        gain = 10.0 * mult * (0.5 + depth)   # depth 0→1 scales reward
        self.current = min(self.current + gain, self.base_allowance * 3)
        self._update_streak()

    def consume(self, cost: float) -> bool:
        if self.current >= cost:
            self.current -= cost
            return True
        return False                     # soft wall: slow drip, not ban

    def _update_streak(self) -> None:
        now = datetime.utcnow()
        if self.last_active and (now - self.last_active) < timedelta(days=2):
            self.streak_days += 1
        else:
            self.streak_days = 1
        self.last_active = now
        # streak bonus
        bonus = 1.0 + 0.25 * min(self.streak_days // 7, 4)
        self.base_allowance = 100.0 * bonus
```

## Why This Beats the Hard Wall

| Hard wall (current) | Soft gradient (proposed) |
|---------------------|---------------------------|
| "Come back in 24h"   | "You've earned 40 more units — keep going" |
| Feature removed      | Feature unlocked by engagement |
| Idle = punished      | Idle = slow drip, not ban |
| Shallow spam rewarded| Depth rewarded, spam penalized |
| Users feel taken from| Users feel invited in |

## Next Steps

1. Prototype the `EngagementProfile` in a sandbox.
2. A/B test against current hard-wall cohort.
3. Instrument: measure retention, depth, and compute cost per engaged user.
4. If retention rises without cost explosion, propose to xAI product as a consumer-tier experiment.

## Notes

- This is a **design artifact**, not a production change to Grok.
- The physics (resonance, weights, soft saturation) is the same as the thruster and shaker work already in this repo.
- The goal is to turn "you've hit your limit" into "you've earned more headroom."
