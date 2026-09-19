"""Alert agent: parses, validates and normalises vendor alerts into the store."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from socagent.db import AlertStore
from socagent.errors import IngestError
from socagent.models import Alert, IngestReport
from socagent.normalizers import NORMALIZERS, NormalizeError
from socagent.security import redact

_MAX_ERRORS = 20


class AlertAgent:
    """Reads JSON Lines exports from a named source and stores normalised alerts."""

    def __init__(
        self, store: AlertStore, *, max_line_bytes: int = 200_000, max_lines: int = 1_000_000
    ) -> None:
        self._store = store
        self._max_line_bytes = max_line_bytes
        self._max_lines = max_lines

    def ingest_lines(self, lines: Iterable[str], source: str) -> IngestReport:
        """Ingest JSON Lines. Bad lines are counted and described (without content), never fatal.

        Raises:
            IngestError: If ``source`` is unknown or the input exceeds the line limit.
        """
        normalizer = NORMALIZERS.get(source)
        if normalizer is None:
            raise IngestError(
                f"unknown source {source!r}; choose from {', '.join(sorted(NORMALIZERS))}"
            )
        report = IngestReport()
        batch: list[Alert] = []

        def reject(number: int, reason: str) -> None:
            report.rejected += 1
            if len(report.errors) < _MAX_ERRORS:
                report.errors.append(f"line {number}: {redact(reason)[:200]}")

        for number, raw in enumerate(lines, start=1):
            if not raw.strip():
                continue
            report.lines += 1
            if report.lines > self._max_lines:
                raise IngestError(f"input exceeds the limit of {self._max_lines} lines")
            if len(raw.encode("utf-8", errors="replace")) > self._max_line_bytes:
                reject(number, f"line exceeds {self._max_line_bytes} bytes")
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                reject(number, "not valid JSON")
                continue
            if not isinstance(record, dict):
                reject(number, "record is not a JSON object")
                continue
            try:
                batch.append(normalizer(record))
            except (NormalizeError, ValueError) as exc:
                reject(number, str(exc).splitlines()[0] if str(exc) else "invalid record")
        seen: set[str] = set()
        unique = []
        for alert in batch:
            if alert.id not in seen:
                seen.add(alert.id)
                unique.append(alert)
        report.duplicates += len(batch) - len(unique)
        stored = self._store.insert(unique)
        report.accepted = stored
        report.duplicates += len(unique) - stored
        return report

    def ingest_file(self, path: Path, source: str) -> IngestReport:
        """Ingest a JSON Lines file. Raises :class:`IngestError` if it cannot be read."""
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                return self.ingest_lines(handle, source)
        except OSError as exc:
            raise IngestError(f"cannot read {path}: {exc.strerror or exc}") from exc
