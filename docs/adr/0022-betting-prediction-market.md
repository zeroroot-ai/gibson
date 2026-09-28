# Betting: a self-calibrating prediction market over hypotheses

An agent stakes calibrated confidence on a hypothesis ([ADR-0021](0021-agents-emit-hypotheses.md)).
The outcome settles the bet ([ADR-0023](0023-bet-settlement.md)). The settled
history recalibrates belief and updates a reputation that steers the fleet. Betting
is a first-class SDK primitive. It builds on [ADR-0006](0006-closed-loop-learning.md).
See [`CONTEXT.md`](../../CONTEXT.md).

## Decision

1. **A bet is a stake on a hypothesis.** The agent commits a calibrated confidence.
   Being wrong costs standing. A guess with no stake is not a bet.

2. **Settlement scores the bet under a proper scoring rule.** The score is the
   training signal. Over time the system gets provably better-calibrated per
   tenant, and the reliability curve is a first-class, shown metric.

3. **Reputation attaches to technique × environment, never to an agent.** Claude
   members are interchangeable and ephemeral. What is durable is which *kind of
   move* pays off in *this* environment. Reputation persists per tenant and feeds
   two things: the prior strength on new hypotheses of that technique, and the
   priority of pursuing them.

## Consequences

A new member inherits the environment's hard-won judgment on its first turn. The
fleet runs an internal prediction market over hypotheses and self-calibrates per
environment. This is the capability a stateless fleet and a black-box SaaS cannot
reproduce. The scoring rule and the stake accounting are the parts to get right.
