# ADR 0001: Advisory containment with human approval

- Status: Accepted
- Date: 2026-09-19

## Context

Containment actions such as isolating a host or disabling an account can stop an attack, and can also take
down a business service or lock out the wrong person. Alert data is noisy and partly attacker-controlled,
so an automated decision made from it can be steered.

## Decision

The agents only propose actions. Executing one needs a named approver listed in the policy, a senior
approver for high-impact actions, an approval younger than the configured lifetime, and completed
dependencies (a snapshot before isolation). Protected targets cannot be approved at all, and that check
repeats at execution time. The default connector is a dry run. Only notifications and tickets, which
cannot cause an outage, are pre-approved, and they are recorded as approved by `policy`.

## Consequences

- Response is slower than full automation, and the person approving carries the decision. That is the
  intent for a first version.
- The workflow is easy to audit, because every transition is a log entry with an actor.
- Teams that want automation can implement the `Connector` protocol and lower the approval bar in their own
  policy, knowing which guardrails they are removing.
