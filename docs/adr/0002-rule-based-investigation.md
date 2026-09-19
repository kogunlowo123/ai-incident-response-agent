# ADR 0002: Rule-based hypotheses and explained scoring

- Status: Accepted
- Date: 2026-09-19

## Context

An investigation summary is only useful if an analyst can see why it says what it says. A model reading
raw alert text would also be exposed to prompt injection, since attackers control strings such as process
names, user agents and file paths.

## Decision

Hypotheses are deterministic rules over alert techniques, tactics and entities, and each names the alerts
that support it. The risk score is a sum of listed factors. A language model is optional and used only for
the summary paragraph. It receives aggregate counts and hypothesis names, never entity values, titles or
descriptions, and its output is dropped unless every number in it appears in those facts.

## Consequences

- Results are reproducible, testable and explainable. The same input always gives the same incident.
- Coverage is limited to the patterns encoded. New attack shapes need new rules.
- The model can make the summary read better but cannot change any finding or action.
