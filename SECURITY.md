# Security Policy

## Supported versions

Security fixes are released for the latest minor version on the `main` branch.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Do not open a public issue for security reports. Use GitHub's private vulnerability reporting (the
**Report a vulnerability** button on this repository's **Security** tab) and include a description and
impact, the affected version or commit, and a minimal reproduction. Please remove real alert data first.
You can expect an acknowledgement within 3 business days and a triage decision within 10 business days.

## Trust boundary

| Input | Trust |
| ----- | ----- |
| Alert exports | Untrusted. They carry attacker-influenced strings and may be malformed or hostile |
| Policy, asset, identity and indicator files | Trusted operator input |
| Approver and executor names | Claimed, not authenticated. Run the CLI under accounts you control |
| Connector webhook responses | Untrusted. Only the status code decides success |
| Model output for summaries | Untrusted text, accepted only if grounded in supplied facts |

## Security controls

| Threat | Control | Location |
| ------ | ------- | -------- |
| Credentials in command lines or descriptions | Redaction at ingestion, before storage, reports and logs | `security.redact`, `normalizers.py` |
| Malformed or oversized input | Per-line byte limit, total line limit, schema validation | `agents/ingest.py`, `models.py` |
| Leaky error messages | Rejects report line numbers and reasons, never content. CLI errors are redacted | `agents/ingest.py`, `cli.py` |
| Prompt injection into summaries | The model sees only aggregate counts. Output containing numbers absent from the facts is discarded | `agents/summary.py` |
| Steering incidents together with a noisy entity | Hub and noise filtering in correlation | `agents/correlation.py` |
| Unapproved or unauthorised response | Approver allowlist, senior approvers for high impact, dry run by default | `executor.py` |
| Stale approvals | Approval lifetime enforced at execution | `executor.py` |
| Touching critical accounts and hosts | Protected targets are manual-only, checked at approval and again at execution | `containment.py`, `executor.py` |
| Blocking internal addresses | Only external addresses are proposed for blocking | `security.is_private_ip` |
| Tampered history | SHA-256 hash chain verified by `audit --verify` | `db.AuditLog` |
| SQL injection | Bound parameters for every statement | `db.py` |
| Report markup injection | Markdown cells escaped, HTML escaped | `reporting.py` |
| Webhook URL exposure | Held as `SecretStr`, never printed, logged or stored | `config.py`, `executor.py` |
| Vulnerable dependencies | `pip-audit`, CodeQL | `.github/` |

## Known limits

- The audit chain does not stop an operator with database write access from rewriting all of it.
- There is no authentication of approvers.
- Live mode delegates execution to your webhook, whose own controls are outside this project.
