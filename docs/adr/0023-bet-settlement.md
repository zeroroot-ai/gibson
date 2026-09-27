# Bet settlement: objective evidence or a human verdict, never an LLM judge

A bet ([ADR-0022](0022-betting-prediction-market.md)) settles only on objective
evidence recorded to the graph, or on a human verdict. An LLM never judges a bet.
The human verdict is **asynchronous labeling**, never a runtime approval gate, so
this stays consistent with [ADR-0008](0008-autonomous-execution-no-hitl.md) and
builds on [ADR-0006](0006-closed-loop-learning.md). See [`CONTEXT.md`](../../CONTEXT.md).

## Decision

1. **TRUE on demonstrated proof.** The fleet demonstrates the claim in a sandbox
   and records the proof as evidence.
2. **FALSE on bounded exhaustion.** The attempt budget runs out with no proof. This
   is a real, recorded outcome, not silence.
3. **HITL for judgment calls.** Where objective proof is not possible, the human
   verdict settles the bet. This is the `VerdictTruePositive`/`VerdictFalsePositive`
   label that already feeds `braintrain` ([ADR-0006](0006-closed-loop-learning.md)).
4. **No LLM judge.** An LLM judge reintroduces the black box, can be gamed, and
   breaks replay. It is excluded from settlement on purpose.
5. **Open bets earn nothing.** An unsettled bet is the fleet's live agenda. It moves
   no calibration curve until it settles.

## Why HITL here does not reopen ADR-0008

[ADR-0008](0008-autonomous-execution-no-hitl.md) removed HITL as a *runtime
approval gate* that pauses a mission. Settlement HITL never pauses anything: the
bet stays OPEN, the fleet keeps working, and the human verdict arrives out of band
and feeds learning. That is the ADR-0006 label path, not an approval gate.
