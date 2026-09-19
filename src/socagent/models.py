"""Domain models: alerts, entities, incidents, investigations, response actions and audit entries."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(str, Enum):
    """Alert and incident severity, ordered from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher is more severe."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Criticality(str, Enum):
    """Business criticality of an asset."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


class EntityType(str, Enum):
    """Kinds of observable that alerts can reference."""

    HOST = "host"
    USER = "user"
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"


class Entity(BaseModel):
    """A normalised observable. Frozen so it can be used in sets and as a mapping key."""

    model_config = ConfigDict(frozen=True)

    type: EntityType
    value: str = Field(min_length=1, max_length=500)

    @property
    def key(self) -> str:
        """Identity used for correlation, for example ``host:ws-042``."""
        return f"{self.type.value}:{self.value}"


Source = Literal["splunk", "sentinel", "crowdstrike", "elastic", "generic"]


class Alert(BaseModel):
    """A normalised security alert from any source."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=200)
    source: Source
    timestamp: datetime
    title: str = Field(min_length=1, max_length=300)
    severity: Severity
    description: str = Field(default="", max_length=2000)
    category: str = Field(default="", max_length=100)
    entities: list[Entity] = Field(default_factory=list, max_length=100)
    techniques: list[str] = Field(default_factory=list, max_length=30)
    tactics: list[str] = Field(default_factory=list, max_length=30)
    attributes: dict[str, str] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return (
            value.replace(tzinfo=timezone.utc)
            if value.tzinfo is None
            else value.astimezone(timezone.utc)
        )

    @field_validator("attributes")
    @classmethod
    def _attribute_limits(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 30 or any(len(k) > 60 or len(v) > 1000 for k, v in value.items()):
            raise ValueError(
                "at most 30 attributes, keys up to 60 and values up to 1000 characters"
            )
        return value

    def entity_keys(self) -> set[str]:
        """Correlation keys of this alert's entities."""
        return {e.key for e in self.entities}


class IocMatch(BaseModel):
    """A known-bad indicator seen in an incident."""

    entity: str
    kind: str
    confidence: int
    feed: str


class Hypothesis(BaseModel):
    """A testable explanation of what is happening, with the evidence for it."""

    name: str
    confidence: Literal["low", "medium", "high"]
    description: str
    evidence: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    """One alert placed on the incident timeline."""

    time: datetime
    alert_id: str
    source: str
    title: str
    severity: Severity
    tactic: str = ""
    entities: list[str] = Field(default_factory=list)


class Investigation(BaseModel):
    """Investigation agent output."""

    timeline: list[TimelineEntry] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    ioc_matches: list[IocMatch] = Field(default_factory=list)
    affected_hosts: list[str] = Field(default_factory=list)
    affected_users: list[str] = Field(default_factory=list)
    lateral_edges: list[tuple[str, str]] = Field(default_factory=list)
    critical_assets: list[str] = Field(default_factory=list)
    privileged_users: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)


IncidentStatus = Literal["open", "investigating", "contained", "closed"]


class Incident(BaseModel):
    """A group of correlated alerts with its assessment."""

    id: str
    title: str
    severity: Severity
    priority: Literal["P1", "P2", "P3", "P4"]
    risk_score: int
    score_factors: list[str] = Field(default_factory=list)
    alert_ids: list[str]
    first_seen: datetime
    last_seen: datetime
    entities: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    status: IncidentStatus = "open"
    assignee: str = ""
    investigation: Investigation = Field(default_factory=Investigation)
    summary: str = ""


ActionType = Literal[
    "snapshot_host",
    "isolate_host",
    "disable_user",
    "reset_credentials",
    "revoke_sessions",
    "block_ip",
    "block_domain",
    "block_hash",
    "notify_owner",
    "open_ticket",
]
ActionStatus = Literal[
    "pending_approval",
    "approved",
    "rejected",
    "executed",
    "expired",
    "failed",
    "manual_only",
]


class Action(BaseModel):
    """A proposed response action and its approval state."""

    id: str
    incident_id: str
    type: ActionType
    target: str
    urgency: Literal["immediate", "soon", "routine"]
    impact: Literal["low", "medium", "high"]
    reversible: bool
    rationale: str
    evidence: list[str] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    requires_approval: bool = True
    requires_senior: bool = False
    warnings: list[str] = Field(default_factory=list)
    status: ActionStatus = "pending_approval"
    approved_by: str = ""
    approved_at: datetime | None = None
    executed_by: str = ""
    executed_at: datetime | None = None
    result: str = ""


class AuditEntry(BaseModel):
    """One tamper-evident audit record."""

    id: int
    timestamp: datetime
    actor: str
    action: str
    subject: str
    detail: str
    prev_hash: str
    hash: str


class IngestReport(BaseModel):
    """Summary of an alert ingestion run."""

    lines: int = 0
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    errors: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    """Outcome of one triage run."""

    alerts_considered: int
    incidents: list[Incident]
    new_actions: int
    details: dict[str, Any] = Field(default_factory=dict)
