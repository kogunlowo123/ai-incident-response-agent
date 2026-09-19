"""SQLite storage: alerts, incidents, actions and a hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from socagent.errors import StoreError
from socagent.models import Action, Alert, AuditEntry, Incident

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    priority TEXT NOT NULL,
    risk INTEGER NOT NULL,
    status TEXT NOT NULL,
    last_seen REAL NOT NULL,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_incident ON actions (incident_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""

GENESIS = "0" * 64


def _epoch(moment: datetime) -> float:
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).timestamp()


def _moment(value: float) -> datetime:
    return datetime.fromtimestamp(value, tz=timezone.utc)


class Database:
    """A SQLite database with the schema applied. Every statement uses bound parameters."""

    def __init__(self, path: Path | str) -> None:
        self._path = str(path)
        self._depth = 0
        try:
            if self._path != ":memory:":
                Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(self._path)
            self.conn.row_factory = sqlite3.Row
            if self._path != ":memory:":
                self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.executescript(_SCHEMA)
            self.conn.commit()
        except (OSError, sqlite3.Error) as exc:
            raise StoreError(f"cannot open database {self._path}: {exc}") from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit on success, roll back on any exception.

        Transactions nest: only the outermost one commits or rolls back, so several stores can
        take part in one atomic change (for example an action's new status and its audit entry).
        """
        self._depth += 1
        try:
            yield self.conn
        except Exception:
            self._depth -= 1
            if self._depth == 0:
                self.conn.rollback()
            raise
        else:
            self._depth -= 1
            if self._depth == 0:
                self.conn.commit()

    def close(self) -> None:
        """Close the connection."""
        self.conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class AlertStore:
    """Persistence for normalised alerts."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def insert(self, alerts: list[Alert]) -> int:
        """Insert alerts, ignoring ids that already exist. Returns the number newly stored."""
        rows = [(a.id, _epoch(a.timestamp), a.source, a.model_dump_json()) for a in alerts]
        with self._db.transaction() as conn:
            before = conn.total_changes
            conn.executemany("INSERT OR IGNORE INTO alerts VALUES (?,?,?,?)", rows)
            return conn.total_changes - before

    def window(self, start: datetime, end: datetime) -> list[Alert]:
        """Alerts with ``start <= timestamp <= end``, oldest first."""
        rows = self._db.conn.execute(
            "SELECT payload FROM alerts WHERE ts >= ? AND ts <= ? ORDER BY ts, id",
            (_epoch(start), _epoch(end)),
        ).fetchall()
        return [Alert.model_validate_json(r["payload"]) for r in rows]

    def get_many(self, ids: list[str]) -> list[Alert]:
        """Alerts with the given ids, oldest first."""
        if not ids:
            return []
        marks = ",".join("?" for _ in ids)
        rows = self._db.conn.execute(
            f"SELECT payload FROM alerts WHERE id IN ({marks}) ORDER BY ts, id",  # noqa: S608
            ids,
        ).fetchall()
        return [Alert.model_validate_json(r["payload"]) for r in rows]

    def count(self) -> int:
        return int(self._db.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])


class IncidentStore:
    """Persistence for incidents. Status and assignee survive re-correlation."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, incident_id: str) -> Incident | None:
        row = self._db.conn.execute(
            "SELECT payload FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return Incident.model_validate_json(row["payload"]) if row else None

    def _write(self, incident: Incident) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?)",
                (
                    incident.id,
                    incident.priority,
                    incident.risk_score,
                    incident.status,
                    _epoch(incident.last_seen),
                    incident.model_dump_json(),
                ),
            )

    def upsert(self, incident: Incident) -> Incident:
        """Store ``incident``, keeping the analyst-set status and assignee of an existing one."""
        existing = self.get(incident.id)
        if existing is not None:
            incident = incident.model_copy(
                update={"status": existing.status, "assignee": existing.assignee}
            )
        self._write(incident)
        return incident

    def update_status(self, incident_id: str, status: str, assignee: str | None = None) -> Incident:
        """Set an incident's status (and optionally its assignee)."""
        incident = self.get(incident_id)
        if incident is None:
            raise StoreError(f"incident {incident_id} not found")
        changes: dict[str, str] = {"status": status}
        if assignee is not None:
            changes["assignee"] = assignee
        updated = incident.model_copy(update=changes)
        self._write(updated)
        return updated

    def list(self, status: str | None = None) -> list[Incident]:
        """Incidents ordered by priority then risk."""
        sql = "SELECT payload FROM incidents"
        params: tuple[str, ...] = ()
        if status:
            sql, params = sql + " WHERE status = ?", (status,)
        rows = self._db.conn.execute(sql, params).fetchall()
        incidents = [Incident.model_validate_json(r["payload"]) for r in rows]
        return sorted(incidents, key=lambda i: (i.priority, -i.risk_score, i.id))

    def resolve_prefix(self, prefix: str) -> Incident:
        """The single incident whose id starts with ``prefix``."""
        matches = [i for i in self.list() if i.id.startswith(prefix)]
        if len(matches) != 1:
            raise StoreError(f"{len(matches)} incidents match '{prefix}'")
        return matches[0]


class ActionStore:
    """Persistence for response actions."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, action_id: str) -> Action | None:
        row = self._db.conn.execute(
            "SELECT payload FROM actions WHERE id = ?", (action_id,)
        ).fetchone()
        return Action.model_validate_json(row["payload"]) if row else None

    def save(self, action: Action) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO actions VALUES (?,?,?,?)",
                (action.id, action.incident_id, action.status, action.model_dump_json()),
            )

    def for_incident(self, incident_id: str) -> list[Action]:
        rows = self._db.conn.execute(
            "SELECT payload FROM actions WHERE incident_id = ? ORDER BY id", (incident_id,)
        ).fetchall()
        return [Action.model_validate_json(r["payload"]) for r in rows]

    def all(self, status: str | None = None) -> list[Action]:
        sql = "SELECT payload FROM actions"
        params: tuple[str, ...] = ()
        if status:
            sql, params = sql + " WHERE status = ?", (status,)
        rows = self._db.conn.execute(sql + " ORDER BY incident_id, id", params).fetchall()
        return [Action.model_validate_json(r["payload"]) for r in rows]

    def resolve_prefix(self, prefix: str) -> Action:
        """The single action whose id starts with ``prefix``."""
        matches = [a for a in self.all() if a.id.startswith(prefix)]
        if len(matches) != 1:
            raise StoreError(f"{len(matches)} actions match '{prefix}'")
        return matches[0]


class AuditLog:
    """Append-only audit log. Each entry's hash covers its content and the previous hash.

    Editing, deleting or reordering any past entry breaks the chain, which :meth:`verify` detects.
    """

    def __init__(self, db: Database, clock: Callable[[], datetime] | None = None) -> None:
        self._db = db
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _digest(prev: str, ts: float, actor: str, action: str, subject: str, detail: str) -> str:
        body = json.dumps(
            [prev, ts, actor, action, subject, detail], separators=(",", ":"), sort_keys=True
        )
        return hashlib.sha256(body.encode()).hexdigest()

    def append(self, actor: str, action: str, subject: str, detail: str = "") -> AuditEntry:
        """Add an entry. It joins the caller's transaction when one is open."""
        with self._db.transaction() as conn:
            last = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            ts = _epoch(self._clock())
            digest = self._digest(prev, ts, actor, action, subject, detail)
            cursor = conn.execute(
                "INSERT INTO audit_log (ts, actor, action, subject, detail, prev_hash, hash) VALUES (?,?,?,?,?,?,?)",
                (ts, actor, action, subject, detail, prev, digest),
            )
        return AuditEntry(
            id=int(cursor.lastrowid or 0),
            timestamp=_moment(ts),
            actor=actor,
            action=action,
            subject=subject,
            detail=detail,
            prev_hash=prev,
            hash=digest,
        )

    def entries(self, limit: int | None = None) -> list[AuditEntry]:
        """Entries oldest first (the most recent ``limit`` when given)."""
        rows = self._db.conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        if limit:
            rows = rows[-limit:]
        return [
            AuditEntry(
                id=r["id"],
                timestamp=_moment(r["ts"]),
                actor=r["actor"],
                action=r["action"],
                subject=r["subject"],
                detail=r["detail"],
                prev_hash=r["prev_hash"],
                hash=r["hash"],
            )
            for r in rows
        ]

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain. Returns ``(True, "")`` or ``(False, reason)``."""
        prev = GENESIS
        for r in self._db.conn.execute("SELECT * FROM audit_log ORDER BY id").fetchall():
            if r["prev_hash"] != prev:
                return False, f"entry {r['id']}: previous hash does not match"
            expected = self._digest(
                prev, r["ts"], r["actor"], r["action"], r["subject"], r["detail"]
            )
            if r["hash"] != expected:
                return False, f"entry {r['id']}: content does not match its hash"
            prev = r["hash"]
        return True, ""
