# ADR 0003: Tolerant per-vendor normalization

- Status: Accepted
- Date: 2026-09-19

## Context

SIEM and EDR exports differ by product, version, and how each team configured them. Fields are sometimes
flat with dotted names and sometimes nested. Strict parsers fail on the first unexpected record.

## Decision

Each vendor has one normalizer that looks up several candidate field names in both layouts, and produces a
single `Alert` model. Records that cannot be normalized are counted and reported by line number, without
echoing their content. Timestamps become UTC. Missing optional fields stay empty rather than being guessed.
Sources are ingested from JSON Lines files, which every one of these products can export or forward to.

## Consequences

- One bad line does not stop an import, and a report shows how many were skipped.
- The mappings are based on public documentation and synthetic samples. They must be checked against real
  exports, and the README says so.
- Adding a vendor is one function, one registry entry and its tests.
