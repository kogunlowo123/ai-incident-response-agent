"""Containment agent: turns an investigation into a prioritised, guarded set of response proposals.

The agent only proposes. Nothing here changes any system. Protected assets, accounts and addresses
are never proposed for automated action, and disruptive actions always need human approval.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import datetime, timezone

from socagent.config import Context, Policy
from socagent.models import Action, ActionType, Alert, Criticality, EntityType, Incident
from socagent.security import is_private_ip

_APPROVAL_FREE: set[str] = {"notify_owner", "open_ticket"}


def action_id(incident_id: str, action_type: str, target: str) -> str:
    """Stable id, so re-running triage updates rather than duplicates actions."""
    return (
        "ACT-"
        + hashlib.sha256(f"{incident_id}|{action_type}|{target}".encode()).hexdigest()[:10].upper()
    )


class ContainmentAgent:
    """Recommends actions from hypotheses, indicator matches and asset context."""

    def __init__(
        self, context: Context, policy: Policy, clock: Callable[[], datetime] | None = None
    ) -> None:
        self._context = context
        self._policy = policy
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def recommend(self, incident: Incident, alerts: list[Alert]) -> list[Action]:
        """Return proposals for ``incident`` in a sensible execution order."""
        inv = incident.investigation
        names = {h.name: h for h in inv.hypotheses}
        proposals: dict[tuple[str, str], Action] = {}
        urgent = incident.priority == "P1" or "ransomware" in names or "lateral_movement" in names
        urgency = (
            "immediate" if urgent else "soon" if incident.priority in ("P1", "P2") else "routine"
        )

        def add(
            kind: ActionType,
            target: str,
            reason: str,
            evidence: list[str],
            *,
            depends: list[str] | None = None,
            when: str | None = None,
        ) -> None:
            key = (kind, target)
            if key in proposals:
                return
            proposals[key] = self._build(
                incident, kind, target, reason, evidence, depends or [], when or urgency
            )

        hosts_by_hypothesis: dict[str, list[str]] = {}
        for hypothesis in inv.hypotheses:
            evidence_alerts = [a for a in alerts if a.id in hypothesis.evidence]
            hosts_by_hypothesis[hypothesis.name] = sorted(
                {v.value for a in evidence_alerts for v in a.entities if v.type is EntityType.HOST}
            )

        credential = names.get("credential_compromise")
        if credential:
            users = (
                sorted(
                    {
                        v.value
                        for a in alerts
                        if a.id in credential.evidence
                        for v in a.entities
                        if v.type is EntityType.USER
                    }
                )
                or inv.affected_users
            )
            for user in users:
                add(
                    "reset_credentials",
                    user,
                    "Credential compromise is suspected for this account.",
                    credential.evidence,
                )
                add(
                    "revoke_sessions",
                    user,
                    "Existing sessions may belong to the attacker.",
                    credential.evidence,
                )
                add(
                    "disable_user",
                    user,
                    "Prevent further use of the suspected compromised account until it is reset.",
                    credential.evidence,
                )
                add(
                    "notify_owner",
                    user,
                    "Tell the account owner and their manager.",
                    credential.evidence,
                    when="routine",
                )

        host_driven = [
            names[n]
            for n in ("malware_execution", "phishing_initial_access", "ransomware")
            if n in names
        ]
        for hypothesis in host_driven:
            for host in hosts_by_hypothesis.get(hypothesis.name, []) or inv.affected_hosts:
                snap = action_id(incident.id, "snapshot_host", host)
                add(
                    "snapshot_host",
                    host,
                    "Preserve volatile evidence before the host is isolated.",
                    hypothesis.evidence,
                )
                add(
                    "isolate_host",
                    host,
                    f"{hypothesis.name.replace('_', ' ')} was observed on this host.",
                    hypothesis.evidence,
                    depends=[snap],
                )

        lateral = names.get("lateral_movement")
        if lateral:
            for host in sorted({h for edge in inv.lateral_edges for h in edge}):
                snap = action_id(incident.id, "snapshot_host", host)
                add(
                    "snapshot_host",
                    host,
                    "Preserve evidence on a host involved in lateral movement.",
                    lateral.evidence,
                )
                add(
                    "isolate_host",
                    host,
                    "Host participated in lateral movement.",
                    lateral.evidence,
                    depends=[snap],
                )
            for user in inv.affected_users:
                add(
                    "disable_user",
                    user,
                    "Account was used during lateral movement.",
                    lateral.evidence,
                )

        for hypothesis_name in ("data_exfiltration", "malware_execution"):
            named = names.get(hypothesis_name)
            if named:
                for alert in (a for a in alerts if a.id in named.evidence):
                    for entity in alert.entities:
                        if (
                            entity.type is EntityType.IP
                            and not is_private_ip(entity.value)
                            and f"ip:{entity.value}" in self._context.indicators
                        ):
                            add(
                                "block_ip",
                                entity.value,
                                "Known-bad address contacted by an affected host.",
                                [alert.id],
                            )
        for match in inv.ioc_matches:
            kind, _, value = match.entity.partition(":")
            evidence = [a.id for a in alerts if match.entity in a.entity_keys()]
            if kind == "ip" and not is_private_ip(value):
                add(
                    "block_ip",
                    value,
                    f"Matches a {match.kind} indicator ({match.feed}, confidence {match.confidence}).",
                    evidence,
                )
            elif kind == "domain":
                add(
                    "block_domain",
                    value,
                    f"Matches a {match.kind} indicator ({match.feed}, confidence {match.confidence}).",
                    evidence,
                )
            elif kind == "hash":
                add(
                    "block_hash",
                    value,
                    f"Matches a {match.kind} indicator ({match.feed}, confidence {match.confidence}).",
                    evidence,
                )

        if "ransomware" in names:
            for user in inv.affected_users:
                add(
                    "disable_user",
                    user,
                    "Accounts active on ransomware-affected hosts may be compromised.",
                    names["ransomware"].evidence,
                )
        if names.get("data_exfiltration"):
            for user in inv.affected_users:
                add(
                    "revoke_sessions",
                    user,
                    "Cut off sessions that could continue exfiltration.",
                    names["data_exfiltration"].evidence,
                )

        if incident.priority in ("P1", "P2"):
            add(
                "open_ticket",
                incident.id,
                "Track the incident and the response.",
                [],
                when="routine",
            )
            for host in inv.critical_assets:
                owner = self._context.assets[host].owner if host in self._context.assets else ""
                if owner:
                    add(
                        "notify_owner",
                        owner,
                        f"Asset {host} is business-critical and is involved.",
                        [],
                        when="soon",
                    )

        order = {
            "snapshot_host": 0,
            "isolate_host": 1,
            "block_ip": 2,
            "block_domain": 2,
            "block_hash": 2,
            "revoke_sessions": 3,
            "reset_credentials": 4,
            "disable_user": 4,
            "notify_owner": 5,
            "open_ticket": 6,
        }
        return sorted(
            proposals.values(),
            key=lambda a: (
                ["immediate", "soon", "routine"].index(a.urgency),
                order[a.type],
                a.target,
            ),
        )

    # construction and guardrails

    def _build(
        self,
        incident: Incident,
        kind: ActionType,
        target: str,
        reason: str,
        evidence: list[str],
        depends: list[str],
        urgency: str,
    ) -> Action:
        warnings: list[str] = []
        impact = {
            "snapshot_host": "low",
            "isolate_host": "medium",
            "disable_user": "medium",
            "reset_credentials": "medium",
        }.get(kind, "low")
        reversible = kind not in {"reset_credentials"}
        senior = False

        if kind in {"isolate_host", "snapshot_host"}:
            asset = self._context.assets.get(target)
            criticality = asset.criticality if asset else None
            if kind == "isolate_host" and criticality in (Criticality.HIGH, Criticality.CRITICAL):
                impact, senior = "high", criticality is Criticality.CRITICAL
                warnings.append(
                    f"{target} is a {criticality.value}-criticality asset; isolation may interrupt a business service."
                )
            if (
                kind == "isolate_host"
                and target not in self._context.assets
                and self._context.assets
            ):
                warnings.append(f"{target} is not in the asset inventory; its role is unknown.")
        if kind in {"disable_user", "reset_credentials", "revoke_sessions"}:
            identity = self._context.identities.get(target)
            if identity and (identity.service_account or identity.privileged):
                impact, senior = "high", True
                warnings.append(
                    f"{target} is a {'service' if identity.service_account else 'privileged'} account; changes may break dependent systems."
                )

        protected = (
            (kind in {"isolate_host", "snapshot_host"} and target in self._policy.protected_hosts)
            or (
                kind in {"disable_user", "reset_credentials", "revoke_sessions"}
                and target in self._policy.protected_users
            )
            or (kind == "block_ip" and target in self._policy.protected_ips)
        )
        approval_free = kind in _APPROVAL_FREE
        status = "manual_only" if protected else "approved" if approval_free else "pending_approval"
        if protected:
            warnings.append(
                "Target is protected by policy: automated action is not permitted. Handle manually with the owner."
            )
        if urgency == "immediate" and incident.priority != "P1" and kind == "isolate_host":
            warnings.append("Urgent because the hypothesis is destructive or spreading.")

        return Action(
            id=action_id(incident.id, kind, target),
            incident_id=incident.id,
            type=kind,
            target=target,
            urgency=urgency,
            impact=impact,
            reversible=reversible,
            rationale=reason,
            evidence=evidence,
            depends_on=depends,
            requires_approval=not approval_free,
            requires_senior=senior or (impact == "high" and not approval_free),
            warnings=warnings,
            status=status,
            approved_by="policy" if approval_free and not protected else "",
            approved_at=self._clock() if approval_free and not protected else None,
        )
