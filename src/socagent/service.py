"""Application service: ingestion, triage (correlate, investigate, propose, summarise) and reporting."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

from socagent.agents.containment import ContainmentAgent
from socagent.agents.correlation import CorrelationAgent, incident_id_for
from socagent.agents.ingest import AlertAgent
from socagent.agents.investigation import InvestigationAgent
from socagent.agents.summary import SummaryWriter, facts_for
from socagent.config import Context, Policy, Settings
from socagent.db import ActionStore, AlertStore, AuditLog, Database, IncidentStore
from socagent.errors import SocagentError
from socagent.executor import ActionService
from socagent.models import Action, Incident, IncidentStatus, IngestReport, Severity, TriageResult

_DURATION_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_duration(text: str) -> timedelta:
    """Parse ``90m``, ``24h`` or ``7d`` into a timedelta."""
    if (
        len(text) < 2
        or text[-1] not in _DURATION_UNITS
        or not text[:-1].isdigit()
        or int(text[:-1]) == 0
    ):
        raise SocagentError(f"invalid duration {text!r}; use forms like 90m, 24h, 7d")
    return timedelta(**{_DURATION_UNITS[text[-1]]: int(text[:-1])})


class IRService:
    """Facade used by the CLI and library callers."""

    def __init__(
        self,
        settings: Settings,
        db: Database,
        alerts: AlertStore,
        incidents: IncidentStore,
        actions: ActionStore,
        audit: AuditLog,
        action_service: ActionService,
        context: Context,
        policy: Policy,
        summary_writer: SummaryWriter,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.alerts = alerts
        self.incidents = incidents
        self.actions = actions
        self.audit = audit
        self.action_service = action_service
        self.context = context
        self.policy = policy
        self._summary = summary_writer
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._ingest = AlertAgent(
            alerts, max_line_bytes=settings.max_line_bytes, max_lines=settings.max_lines
        )
        self._correlator = CorrelationAgent(policy)
        self._investigator = InvestigationAgent(context, policy)
        self._containment = ContainmentAgent(context, policy, self._clock)

    def close(self) -> None:
        """Close the database. Safe to call more than once."""
        self.db.close()

    def __enter__(self) -> IRService:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ingestion

    def ingest_file(self, source: str, path: Path) -> IngestReport:
        """Normalise and store the alerts in a JSON Lines export from ``source``."""
        report = self._ingest.ingest_file(path, source)
        self.audit.append(
            "system",
            "alerts.ingest",
            source,
            f"accepted={report.accepted} duplicates={report.duplicates} rejected={report.rejected}",
        )
        return report

    # triage

    def triage(self, *, lookback: timedelta, now: datetime | None = None) -> TriageResult:
        """Correlate recent alerts into incidents, investigate each and propose containment."""
        end = now or self._clock()
        alerts = self.alerts.window(end - lookback, end)
        floor = Severity(self.policy.singleton_min_severity).rank

        saved: list[Incident] = []
        suppressed = new_actions = 0
        for group in self._correlator.correlate(alerts):
            if len(group) == 1 and group[0].severity.rank < floor:
                suppressed += 1
                continue
            incident = self._investigator.build_incident(incident_id_for(group), group)
            proposals = self._containment.recommend(incident, group)
            incident = incident.model_copy(
                update={"summary": self._summary.write(facts_for(incident, proposals))}
            )
            saved.append(self.incidents.upsert(incident))
            new_actions += self.action_service.save_recommendations(proposals)

        merged = self._close_merged(saved)
        self.audit.append(
            "system",
            "triage.run",
            "all",
            f"alerts={len(alerts)} incidents={len(saved)} suppressed={suppressed} merged={merged} new_actions={new_actions}",
        )
        return TriageResult(
            alerts_considered=len(alerts),
            incidents=saved,
            new_actions=new_actions,
            details={"suppressed_singletons": suppressed, "closed_as_merged": merged},
        )

    def _close_merged(self, current: list[Incident]) -> int:
        """Close stored incidents whose alerts now belong to a different, larger incident."""
        current_ids = {i.id for i in current}
        closed = 0
        for old in self.incidents.list():
            if old.id in current_ids or old.status == "closed":
                continue
            target = next((i for i in current if set(old.alert_ids) <= set(i.alert_ids)), None)
            if target is not None:
                self.incidents.update_status(old.id, "closed")
                self.audit.append("system", "incident.merged", old.id, f"merged into {target.id}")
                closed += 1
        return closed

    # queries and updates

    def get_incident(self, prefix: str) -> tuple[Incident, list[Action]]:
        """The incident whose id starts with ``prefix`` and its actions."""
        incident = self.incidents.resolve_prefix(prefix)
        return incident, self.actions.for_incident(incident.id)

    def set_status(
        self, prefix: str, status: IncidentStatus, actor: str, assignee: str | None = None
    ) -> Incident:
        """Change an incident's status (and optionally assignee), recording the change."""
        incident = self.incidents.resolve_prefix(prefix)
        with self.db.transaction():
            updated = self.incidents.update_status(incident.id, status, assignee)
            self.audit.append(
                actor, "incident.status", incident.id, f"{incident.status} -> {status}"
            )
        return updated
