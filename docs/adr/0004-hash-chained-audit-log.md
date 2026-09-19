# ADR 0004: Hash-chained audit log in the same transaction

- Status: Accepted
- Date: 2026-09-19

## Context

Response decisions need a record of who approved what and when. A log that can be edited silently is weak
evidence, and a log written after the state change can disagree with it if the process dies in between.

## Decision

Each audit entry stores the SHA-256 of its content and the previous entry's hash. `audit --verify`
recomputes the chain. Audit rows are written inside the same nested transaction as the state change, so
both commit or both roll back. An execution writes a start entry before it calls the connector.

## Consequences

- Editing, deleting or reordering an old entry is detected.
- Someone with full database access can rewrite the whole chain. Export the log to append-only storage if
  that threat matters.
- Because the connector call cannot be inside a database transaction, a crash after the call but before
  the result is recorded leaves a start entry with no completion. That is visible and safer than silence.
