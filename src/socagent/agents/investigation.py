"""Investigation agent: timeline, indicator matches, asset context, hypotheses and risk scoring."""

from __future__ import annotations

from collections.abc import Callable
from itertools import combinations

from socagent import mitre
from socagent.config import Context, Policy
from socagent.models import (
    Alert,
    Criticality,
    Hypothesis,
    Incident,
    IncidentStatus,
    Investigation,
    IocMatch,
    Severity,
    TimelineEntry,
)

_BRUTE_WORDS = ("brute force", "password spray", "failed logon", "failed login", "multiple failed")
_SUCCESS_WORDS = (
    "successful logon",
    "successful login",
    "successful sign-in",
    "successful signin",
    "login succeeded",
)
_ANOMALY_WORDS = ("impossible travel", "new country", "anomalous sign-in", "unfamiliar", "atypical")
_C2_WORDS = ("beacon", "command and control", "c2 ")

_TITLES = {
    "ransomware": "Ransomware activity",
    "credential_compromise": "Credential compromise",
    "malware_execution": "Malware execution with command and control",
    "phishing_initial_access": "Phishing leading to execution",
    "lateral_movement": "Lateral movement",
    "data_exfiltration": "Possible data exfiltration",
    "multi_stage_activity": "Multi-stage suspicious activity",
}
_HYPOTHESIS_ORDER = list(_TITLES)


def _has_technique(alert: Alert, *prefixes: str) -> bool:
    return any(t.startswith(prefixes) for t in alert.techniques)


def _has_words(alert: Alert, words: tuple[str, ...]) -> bool:
    text = f"{alert.title} {alert.description}".lower()
    return any(w in text for w in words)


def _is_bruteforce(alert: Alert) -> bool:
    return _has_technique(alert, "T1110") or _has_words(alert, _BRUTE_WORDS)


def _is_success(alert: Alert) -> bool:
    return _has_words(alert, _SUCCESS_WORDS)


def _is_execution(alert: Alert) -> bool:
    return "TA0002" in alert.tactics


def _is_c2(alert: Alert) -> bool:
    return "TA0011" in alert.tactics or _has_words(alert, _C2_WORDS)


def _entities(alert: Alert, kind: str) -> set[str]:
    return {e.value for e in alert.entities if e.type.value == kind}


def _ids(alerts: list[Alert]) -> list[str]:
    return [a.id for a in alerts]


def _confidence(*conditions: bool) -> str:
    met = sum(conditions)
    return "high" if met >= 2 else "medium" if met == 1 else "low"


class InvestigationAgent:
    """Builds an :class:`Investigation` and a risk assessment for a group of correlated alerts."""

    def __init__(self, context: Context, policy: Policy) -> None:
        self._context = context
        self._policy = policy

    # public

    def investigate(self, alerts: list[Alert]) -> Investigation:
        """Analyse ``alerts`` and return the findings. Input order does not matter."""
        alerts = sorted(alerts, key=lambda a: (a.timestamp, a.id))
        hosts = sorted({v for a in alerts for v in _entities(a, "host")})
        users = sorted(
            {v for a in alerts for v in _entities(a, "user")} - set(self._policy.noise_users)
        )
        hypotheses = self._hypotheses(alerts)
        lateral = self._lateral_edges(alerts)
        return Investigation(
            timeline=self._timeline(alerts),
            hypotheses=hypotheses,
            ioc_matches=self._iocs(alerts),
            affected_hosts=hosts,
            affected_users=users,
            lateral_edges=lateral,
            critical_assets=[
                h for h in hosts if self._criticality(h) in (Criticality.HIGH, Criticality.CRITICAL)
            ],
            privileged_users=[u for u in users if self._privileged(u)],
            gaps=self._gaps(alerts, hosts, users),
        )

    def assess(self, alerts: list[Alert], inv: Investigation) -> tuple[int, list[str]]:
        """Risk score (0 to 100) and the factors that produced it."""
        factors: list[str] = []
        top = max(alerts, key=lambda a: a.severity.rank).severity
        base = {
            Severity.CRITICAL: 60,
            Severity.HIGH: 45,
            Severity.MEDIUM: 25,
            Severity.LOW: 10,
            Severity.INFO: 3,
        }[top]
        score = base
        factors.append(f"+{base} highest alert severity is {top.value}")

        tactics = {t for a in alerts for t in a.tactics}
        if len(tactics) > 1:
            bonus = min(20, 5 * (len(tactics) - 1))
            score += bonus
            names = ", ".join(
                mitre.TACTICS.get(t, t) for t in sorted(tactics, key=mitre.tactic_order)
            )
            factors.append(f"+{bonus} spans {len(tactics)} tactics ({names})")
        crit = [h for h in inv.critical_assets if self._criticality(h) is Criticality.CRITICAL]
        if crit:
            score += 15
            factors.append(f"+15 involves critical asset(s): {', '.join(crit)}")
        elif inv.critical_assets:
            score += 8
            factors.append(
                f"+8 involves high-criticality asset(s): {', '.join(inv.critical_assets)}"
            )
        if inv.privileged_users:
            score += 10
            factors.append(f"+10 involves privileged account(s): {', '.join(inv.privileged_users)}")
        if inv.ioc_matches:
            score += 15
            factors.append(f"+15 matches {len(inv.ioc_matches)} known-bad indicator(s)")
        if len(alerts) > 5:
            score += 5
            factors.append(f"+5 {len(alerts)} correlated alerts")
        if any(h.name == "ransomware" for h in inv.hypotheses):
            score += 15
            factors.append("+15 ransomware indicators")
        confirmed = [h for h in inv.hypotheses if h.confidence == "high" and h.name != "ransomware"]
        if confirmed:
            score += 10
            factors.append(f"+10 high-confidence hypothesis: {confirmed[0].name.replace('_', ' ')}")
        return min(score, 100), factors

    def build_incident(
        self, incident_id: str, alerts: list[Alert], status: IncidentStatus = "open"
    ) -> Incident:
        """Investigate ``alerts`` and assemble the :class:`Incident`."""
        alerts = sorted(alerts, key=lambda a: (a.timestamp, a.id))
        inv = self.investigate(alerts)
        risk, factors = self.assess(alerts, inv)
        severity = (
            Severity.CRITICAL
            if risk >= 80
            else Severity.HIGH
            if risk >= 60
            else Severity.MEDIUM
            if risk >= 35
            else Severity.LOW
            if risk >= 15
            else Severity.INFO
        )
        priority = "P1" if risk >= 80 else "P2" if risk >= 60 else "P3" if risk >= 35 else "P4"
        primary = inv.hypotheses[0].name if inv.hypotheses else None
        target = self._primary_target(inv, alerts)
        title = (
            f"{_TITLES[primary]}: {target}"
            if primary
            else f"{max(alerts, key=lambda a: a.severity.rank).title[:120]}"
        )
        return Incident(
            id=incident_id,
            title=title,
            severity=severity,
            priority=priority,
            risk_score=risk,
            score_factors=factors,
            alert_ids=_ids(alerts),
            first_seen=alerts[0].timestamp,
            last_seen=alerts[-1].timestamp,
            entities=sorted({k for a in alerts for k in a.entity_keys()}),
            tactics=sorted({t for a in alerts for t in a.tactics}, key=mitre.tactic_order),
            techniques=sorted({t for a in alerts for t in a.techniques}),
            sources=sorted({a.source for a in alerts}),
            status=status,
            investigation=inv,
        )

    @staticmethod
    def _primary_target(inv: Investigation, alerts: list[Alert]) -> str:
        """The entity to name in the title: where the leading hypothesis first shows up."""
        wanted = (
            "user"
            if inv.hypotheses and inv.hypotheses[0].name == "credential_compromise"
            else "host"
        )
        if inv.hypotheses:
            evidence = set(inv.hypotheses[0].evidence)
            for alert in (a for a in alerts if a.id in evidence):
                found = sorted(_entities(alert, wanted))
                if found:
                    return found[0]
        pool = (
            inv.affected_users + inv.affected_hosts
            if wanted == "user"
            else inv.affected_hosts + inv.affected_users
        )
        return pool[0] if pool else "unknown"

    # context lookups

    def _criticality(self, host: str) -> Criticality | None:
        asset = self._context.assets.get(host)
        return asset.criticality if asset else None

    def _privileged(self, user: str) -> bool:
        identity = self._context.identities.get(user)
        return bool(identity and (identity.privileged or identity.service_account))

    def _iocs(self, alerts: list[Alert]) -> list[IocMatch]:
        matches: dict[str, IocMatch] = {}
        for alert in alerts:
            for key in alert.entity_keys():
                indicator = self._context.indicators.get(key)
                if indicator and key not in matches:
                    matches[key] = IocMatch(
                        entity=key,
                        kind=indicator.kind,
                        confidence=indicator.confidence,
                        feed=indicator.source,
                    )
        return sorted(matches.values(), key=lambda m: (-m.confidence, m.entity))

    # analysis

    @staticmethod
    def _timeline(alerts: list[Alert]) -> list[TimelineEntry]:
        rows = []
        for a in alerts:
            tactic = min(a.tactics, key=mitre.tactic_order) if a.tactics else ""
            rows.append(
                TimelineEntry(
                    time=a.timestamp,
                    alert_id=a.id,
                    source=a.source,
                    title=a.title,
                    severity=a.severity,
                    tactic=mitre.TACTICS.get(tactic, tactic),
                    entities=sorted(a.entity_keys()),
                )
            )
        return rows

    @staticmethod
    def _lateral_edges(alerts: list[Alert]) -> list[tuple[str, str]]:
        edges: set[tuple[str, str]] = set()
        for alert in alerts:
            if "TA0008" in alert.tactics or _has_technique(alert, "T1021"):
                hosts = sorted(_entities(alert, "host"))
                edges.update(combinations(hosts, 2))
        return sorted(edges)

    def _gaps(self, alerts: list[Alert], hosts: list[str], users: list[str]) -> list[str]:
        gaps: list[str] = []
        if not self._context.indicators:
            gaps.append("No threat intelligence feed is loaded, so indicator matching was skipped.")
        unknown_hosts = [h for h in hosts if h not in self._context.assets]
        if unknown_hosts and self._context.assets:
            gaps.append(f"Hosts missing from the asset inventory: {', '.join(unknown_hosts)}.")
        if not hosts:
            gaps.append(
                "No endpoint is attributed to this incident, so host-level containment cannot be proposed."
            )
        if not users and self._context.identities:
            gaps.append("No user is attributed to this incident.")
        if len({a.source for a in alerts}) == 1 and len(alerts) > 1:
            gaps.append(
                "Every alert comes from one telemetry source; corroborate with another source."
            )
        return gaps

    def _hypotheses(self, alerts: list[Alert]) -> list[Hypothesis]:
        found: list[Hypothesis] = []
        rules: list[Callable[[list[Alert]], Hypothesis | None]] = [
            self._ransomware,
            self._credential,
            self._malware,
            self._phishing,
            self._lateral,
            self._exfil,
            self._multi_stage,
        ]
        for rule in rules:
            hypothesis = rule(alerts)
            if hypothesis:
                found.append(hypothesis)
        return sorted(
            found,
            key=lambda h: (
                -["low", "medium", "high"].index(h.confidence),
                _HYPOTHESIS_ORDER.index(h.name),
            ),
        )

    @staticmethod
    def _ransomware(alerts: list[Alert]) -> Hypothesis | None:
        hits = [a for a in alerts if _has_technique(a, "T1486", "T1490")]
        if not hits:
            return None
        both = any(_has_technique(a, "T1486") for a in hits) and any(
            _has_technique(a, "T1490") for a in hits
        )
        return Hypothesis(
            name="ransomware",
            confidence="high" if both or len(hits) > 1 else "medium",
            description="Data encryption or recovery-inhibition techniques were observed.",
            evidence=_ids(hits),
            techniques=sorted(
                {t for a in hits for t in a.techniques if t.startswith(("T1486", "T1490"))}
            ),
        )

    @staticmethod
    def _credential(alerts: list[Alert]) -> Hypothesis | None:
        attacks = [a for a in alerts if _is_bruteforce(a)]
        successes = [
            a
            for a in alerts
            if _is_success(a) or (_has_technique(a, "T1078") and not _is_bruteforce(a))
        ]
        anomalies = [a for a in alerts if _has_words(a, _ANOMALY_WORDS)]
        confirmed: list[Alert] = []
        for attack in attacks:
            users = _entities(attack, "user")
            confirmed += [
                s
                for s in successes
                if s.timestamp >= attack.timestamp and users & _entities(s, "user")
            ]
        if not (attacks or anomalies):
            return None
        evidence = list(dict.fromkeys(_ids(attacks) + _ids(confirmed) + _ids(anomalies)))
        return Hypothesis(
            name="credential_compromise",
            confidence=_confidence(bool(attacks), bool(confirmed or (anomalies and successes))),
            description="Repeated authentication attempts"
            + (
                " were followed by a successful sign-in for the same account."
                if confirmed
                else " or anomalous sign-ins were observed."
            ),
            evidence=evidence,
            techniques=sorted({t for a in attacks + confirmed for t in a.techniques}),
        )

    @staticmethod
    def _malware(alerts: list[Alert]) -> Hypothesis | None:
        for execution in (a for a in alerts if _is_execution(a)):
            hosts = _entities(execution, "host")
            c2 = [a for a in alerts if _is_c2(a) and hosts & _entities(a, "host")]
            if c2:
                return Hypothesis(
                    name="malware_execution",
                    confidence="high",
                    description="Code execution and command-and-control activity occurred on the same host.",
                    evidence=list(dict.fromkeys([execution.id, *_ids(c2)])),
                    techniques=sorted({t for a in [execution, *c2] for t in a.techniques}),
                )
        return None

    @staticmethod
    def _phishing(alerts: list[Alert]) -> Hypothesis | None:
        phish = [a for a in alerts if _has_technique(a, "T1566")]
        if not phish:
            return None
        follow = [
            a
            for a in alerts
            if _is_execution(a)
            and any(
                a.timestamp >= p.timestamp
                and (
                    _entities(p, "user") & _entities(a, "user")
                    or _entities(p, "host") & _entities(a, "host")
                )
                for p in phish
            )
        ]
        return Hypothesis(
            name="phishing_initial_access",
            confidence=_confidence(True, bool(follow)),
            description="A phishing alert"
            + (
                " was followed by execution on the same user or host." if follow else " was raised."
            ),
            evidence=list(dict.fromkeys(_ids(phish) + _ids(follow))),
            techniques=sorted({t for a in phish + follow for t in a.techniques}),
        )

    def _lateral(self, alerts: list[Alert]) -> Hypothesis | None:
        hits = [a for a in alerts if "TA0008" in a.tactics or _has_technique(a, "T1021")]
        if not hits:
            return None
        multi = bool(self._lateral_edges(alerts))
        return Hypothesis(
            name="lateral_movement",
            confidence=_confidence(True, multi),
            description="Remote-service activity links multiple hosts."
            if multi
            else "Remote-service activity was observed.",
            evidence=_ids(hits),
            techniques=sorted({t for a in hits for t in a.techniques}),
        )

    @staticmethod
    def _exfil(alerts: list[Alert]) -> Hypothesis | None:
        hits = [a for a in alerts if "TA0010" in a.tactics or _has_technique(a, "T1041", "T1048")]
        if not hits:
            return None
        corroborated = any(
            _is_c2(a) or "TA0008" in a.tactics or "TA0009" in a.tactics for a in alerts
        )
        return Hypothesis(
            name="data_exfiltration",
            confidence=_confidence(True, corroborated),
            description="Exfiltration techniques were observed"
            + (" alongside command-and-control or lateral activity." if corroborated else "."),
            evidence=_ids(hits),
            techniques=sorted({t for a in hits for t in a.techniques}),
        )

    @staticmethod
    def _multi_stage(alerts: list[Alert]) -> Hypothesis | None:
        tactics = {t for a in alerts for t in a.tactics}
        if len(tactics) < 3 or len(alerts) < 2:
            return None
        return Hypothesis(
            name="multi_stage_activity",
            confidence="medium",
            description=f"Alerts span {len(tactics)} distinct attack tactics in one correlated group.",
            evidence=_ids(alerts),
            techniques=[],
        )
