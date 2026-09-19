# Contributing

Thanks for helping improve this project. This guide covers the workflow and the quality bar.

## Development setup

```bash
git clone <repository-url>
cd ai-incident-response-agent
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Checks

Every change must pass the gates CI enforces:

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy --strict
make cov         # pytest with a coverage gate of 80%
```

`make format` applies safe autofixes and formatting.

## Workflow

1. Open an issue for anything larger than a small fix so the design can be discussed first.
2. Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
3. Keep commits focused, with imperative subjects.
4. Add or update tests. Bug fixes need a regression test that fails without the fix.
5. Update `CHANGELOG.md` under **Unreleased** and any affected documentation.
6. Open a pull request describing the problem, the approach and how you verified it.

## Code standards

- Python 3.10+, fully type-annotated, `mypy --strict` clean.
- Docstrings explain behaviour, not restate names.
- Errors raised deliberately derive from `SocagentError`.
- Redact anything that can hold a secret (command lines, descriptions) before it is stored or logged.
- Never send raw alert text or entity values to a language model.
- Every SQL statement uses bound parameters.
- State changes and their audit entries go in one transaction, and every new transition writes an audit entry.
- Close database connections (`IRService` is a context manager).
- Tests are offline and deterministic: temporary SQLite files, the simulator, `httpx.MockTransport` and
  injected clocks (see `tests/conftest.py`).

## Adding a vendor normalizer

1. Write `def myvendor(raw: dict[str, Any]) -> Alert` in `normalizers.py`. Use `first`, `dig`, `EntityBag`
   and `build` so lookups tolerate flat and nested layouts and command lines are redacted.
2. Register it in `NORMALIZERS` and add the source to the `Alert.source` literal.
3. Test it with a representative record from a real export (with sensitive values replaced), plus a record
   with missing fields.

## Adding a hypothesis or action

Hypotheses are rules in `InvestigationAgent._hypotheses` that return the supporting alert ids. New action
types need an entry in `ActionType`, an ordering in `ContainmentAgent.recommend`, and an impact and
reversibility decision in `_build`. Cover both the firing case and the protected-target case.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## License

By contributing you agree that your contributions are licensed under the MIT License.
