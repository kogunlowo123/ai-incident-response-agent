"""Markdown and JSON incident reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from socagent import mitre
from socagent.errors import ReportError
from socagent.models import Action, Incident

FORMATS = ("md", "json")
_NOTICE = (
    "This report is generated from the alerts ingested and the context files loaded. Hypotheses are "
    "rule-based inferences, not confirmed findings, and every proposed action requires human review "
    "before it is approved. Normalisation of vendor alerts should be validated against your own "
    "exports, and ATT&CK identifiers against the current release."
)


def _cell(value: Any) -> str:
    return (
        str(value).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;").replace(">", "&gt;")
    )


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    if not rows:
        return ["None.", ""]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return [*lines, ""]


class IncidentReport(BaseModel):
    """Serialisable incident report."""

    schema_version: str = "1.0"
    incident: Incident
    actions: list[Action]


def render_markdown(incident: Incident, actions: list[Action]) -> str:
    """Render one incident as a Markdown document."""
    inv = incident.investigation
    out: list[str] = [
        f"# {_cell(incident.id)}: {_cell(incident.title)}",
        "",
        f"Priority **{incident.priority}**, severity **{incident.severity.value}**, risk score **{incident.risk_score}/100**, "
        f"status **{incident.status}**. First seen {incident.first_seen.isoformat()}, last seen {incident.last_seen.isoformat()}.",
        "",
        "## Summary",
        "",
        _cell(incident.summary),
        "",
        "## Why this score",
        "",
        *[f"- {_cell(f)}" for f in incident.score_factors],
        "",
        "## Hypotheses",
        "",
        *_table(
            ["Hypothesis", "Confidence", "Basis", "Evidence"],
            [
                [h.name.replace("_", " "), h.confidence, h.description, ", ".join(h.evidence)]
                for h in inv.hypotheses
            ],
        ),
        "## Timeline",
        "",
        *_table(
            ["Time (UTC)", "Source", "Severity", "Tactic", "Alert", "Entities"],
            [
                [
                    e.time.strftime("%Y-%m-%d %H:%M:%S"),
                    e.source,
                    e.severity.value,
                    e.tactic or "-",
                    e.title,
                    ", ".join(e.entities),
                ]
                for e in inv.timeline
            ],
        ),
        "## Scope",
        "",
        f"- Hosts: {_cell(', '.join(inv.affected_hosts) or 'none')}",
        f"- Users: {_cell(', '.join(inv.affected_users) or 'none')}",
        f"- Critical assets: {_cell(', '.join(inv.critical_assets) or 'none')}",
        f"- Privileged or service accounts: {_cell(', '.join(inv.privileged_users) or 'none')}",
        f"- Host relationships from lateral movement: {_cell('; '.join(f'{a} <-> {b}' for a, b in inv.lateral_edges) or 'none')}",
        "",
        "## Known-bad indicators",
        "",
        *_table(
            ["Indicator", "Kind", "Confidence", "Feed"],
            [[m.entity, m.kind, m.confidence, m.feed] for m in inv.ioc_matches],
        ),
        "## ATT&CK mapping",
        "",
        *_table(
            ["Technique", "Name", "Tactic"],
            [
                [t, mitre.technique_name(t), mitre.TACTICS.get(mitre.tactic_for(t) or "", "-")]
                for t in incident.techniques
            ],
        ),
        "## Proposed response actions",
        "",
        "Nothing below has been done unless its status says executed. Approval is a human decision.",
        "",
        *_table(
            [
                "Id",
                "Action",
                "Target",
                "Urgency",
                "Impact",
                "Status",
                "Approval",
                "Depends on",
                "Warnings",
            ],
            [
                [
                    a.id,
                    a.type.replace("_", " "),
                    a.target,
                    a.urgency,
                    a.impact,
                    a.status,
                    "senior"
                    if a.requires_senior
                    else "required"
                    if a.requires_approval
                    else "not needed",
                    ", ".join(a.depends_on) or "-",
                    " ".join(a.warnings) or "-",
                ]
                for a in actions
            ],
        ),
        "## Gaps and open questions",
        "",
        *([f"- {_cell(g)}" for g in inv.gaps] or ["None identified."]),
        "",
        "## Notice",
        "",
        _NOTICE,
        "",
    ]
    return "\n".join(out)


def render(incident: Incident, actions: list[Action], fmt: str) -> str:
    """Render ``incident`` as ``md`` or ``json``."""
    if fmt == "md":
        return render_markdown(incident, actions)
    if fmt == "json":
        return IncidentReport(incident=incident, actions=actions).model_dump_json(indent=2)
    raise ReportError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}")


def write_report(
    incident: Incident, actions: list[Action], out_dir: Path, formats: list[str]
) -> list[Path]:
    """Write reports named ``<incident id>.<ext>`` into ``out_dir``."""
    rendered = {fmt: render(incident, actions, fmt) for fmt in formats}
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        paths = []
        for fmt, content in rendered.items():
            path = out_dir / f"{incident.id}.{fmt}"
            path.write_text(content, encoding="utf-8")
            paths.append(path)
    except OSError as exc:
        raise ReportError(f"cannot write report to {out_dir}: {exc}") from exc
    return paths
