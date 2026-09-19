"""Unit tests for config, storage, correlation, investigation, containment and summaries."""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr

from socagent.agents.containment import ContainmentAgent, action_id
from socagent.agents.correlation import CorrelationAgent, incident_id_for
from socagent.agents.investigation import InvestigationAgent
from socagent.agents.summary import LLMSummaryWriter, SummaryFacts, TemplateSummaryWriter, facts_for
from socagent.config import Context, Policy, Settings, load_context, load_policy
from socagent.container import build_service
from socagent.db import ActionStore, AlertStore, AuditLog, Database, IncidentStore
from socagent.errors import ConfigurationError, ProviderError, StoreError
from socagent.models import Alert, Criticality, Incident
from socagent.service import parse_duration
from tests.conftest import CONFIGS, NOW, START, make_alert, make_settings, write_configs

HASH = "a" * 64


def _write_case(tmp_path: Path, data: dict[str, object]) -> tuple[Path | None, Path | None]:
    if "indicators" in data:
        path = tmp_path / "case_iocs.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return None, path
    path = tmp_path / "case_assets.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path, None


class TestConfig:
    def test_example_configs_load(self) -> None:
        ctx = load_context(CONFIGS / "assets.example.yaml", CONFIGS / "iocs.example.json")
        assert ctx.assets["dc01"].criticality is Criticality.CRITICAL
        assert ctx.identities["admin.jsmith"].privileged and ctx.indicators
        policy = load_policy(CONFIGS / "policy.example.yaml")
        assert "dc01" in policy.protected_hosts and policy.senior_approvers == ["soc-lead"]

    def test_defaults_when_no_files(self) -> None:
        assert load_policy(None) == Policy() and load_context(None, None) == Context()

    def test_policy_values_are_normalised(self) -> None:
        policy = Policy(
            protected_hosts=["DC01.", "bad host!"],
            protected_users=["CORP\\Breakglass"],
            protected_ips=["not-ip", "203.0.113.9"],
        )
        assert policy.protected_hosts == ["dc01"]
        assert policy.protected_users == ["breakglass"]
        assert policy.protected_ips == ["203.0.113.9"]

    def test_bad_policy_files_raise_configuration_error(self, tmp_path: Path) -> None:
        listing = tmp_path / "list.yaml"
        listing.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="mapping"):
            load_policy(listing)
        with pytest.raises(ConfigurationError):
            load_policy(tmp_path / "missing.yaml")
        unknown = tmp_path / "unknown.yaml"
        unknown.write_text("surprise: 1\n", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="invalid policy"):
            load_policy(unknown)
        broken = tmp_path / "broken.yaml"
        broken.write_text("a: [unclosed\n", encoding="utf-8")
        with pytest.raises(ConfigurationError):
            load_policy(broken)

    @pytest.mark.parametrize(
        "case",
        [
            {"assets": [{"name": "bad host!"}]},
            {"assets": [{"name": "h1", "criticality": "enormous"}]},
            {"identities": [{"name": "  "}]},
            {"indicators": [{"type": "ip", "value": "999.9.9.9"}]},
            {"indicators": [{"type": "url", "value": "x"}]},
        ],
    )
    def test_bad_context_raises(self, tmp_path: Path, case: dict[str, object]) -> None:
        with pytest.raises(ConfigurationError):
            load_context(*_write_case(tmp_path, case))

    def test_unreadable_indicator_files(self, tmp_path: Path) -> None:
        iocs = tmp_path / "iocs.json"
        iocs.write_text("{not json", encoding="utf-8")
        with pytest.raises(ConfigurationError, match="indicators"):
            load_context(None, iocs)
        with pytest.raises(ConfigurationError):
            load_context(None, tmp_path / "nope.json")

    def test_indicators_are_normalised(self, tmp_path: Path) -> None:
        overrides = write_configs(
            tmp_path,
            indicators=[
                {"type": "hash", "value": "A" * 64},
                {"type": "domain", "value": "Evil.Example."},
            ],
        )
        ctx = load_context(None, overrides["iocs_file"])  # type: ignore[arg-type]
        assert set(ctx.indicators) == {"hash:" + "a" * 64, "domain:evil.example"}

    def test_settings_validation(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="CONNECTOR_URL"):
            make_settings(tmp_path, execution_mode="live")
        with pytest.raises(ValueError, match="retry_max_wait"):
            make_settings(tmp_path, retry_min_wait=5.0, retry_max_wait=1.0)
        live = make_settings(
            tmp_path,
            execution_mode="live",
            connector_url=SecretStr("https://soar.example/hook/token123"),
        )
        assert "token123" not in repr(live)

    def test_env_example_parses(self) -> None:
        settings = Settings(_env_file=CONFIGS.parent / ".env.example")  # type: ignore[call-arg]
        assert settings.execution_mode == "dry_run" and settings.llm_provider == "none"

    @pytest.mark.parametrize("provider", ["openai", "anthropic"])
    def test_provider_credentials_required(self, tmp_path: Path, provider: str) -> None:
        settings = make_settings(
            tmp_path, llm_provider=provider, openai_api_key=None, anthropic_api_key=None
        )
        with pytest.raises(ConfigurationError, match="API_KEY"):
            build_service(settings)


class TestDuration:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [("90m", timedelta(minutes=90)), ("24h", timedelta(hours=24)), ("7d", timedelta(days=7))],
    )
    def test_valid(self, text: str, expected: timedelta) -> None:
        assert parse_duration(text) == expected

    @pytest.mark.parametrize("text", ["", "h", "0h", "5x", "-3h", "1.5h", "24"])
    def test_invalid(self, text: str) -> None:
        with pytest.raises(Exception, match="invalid duration"):
            parse_duration(text)


def _incident(
    alerts: list[Alert], ctx: Context | None = None, policy: Policy | None = None
) -> Incident:
    agent = InvestigationAgent(ctx or Context(), policy or Policy())
    return agent.build_incident(incident_id_for(alerts), alerts)


class TestStores:
    def test_alert_store_dedupes_and_windows(self, tmp_path: Path) -> None:
        store = AlertStore(Database(tmp_path / "s.db"))
        alerts = [
            make_alert("a1", 0, hosts=["h1"]),
            make_alert("a2", 30, users=["u"]),
            make_alert("a3", 600),
        ]
        assert store.insert(alerts) == 3 and store.insert(alerts) == 0 and store.count() == 3
        window = store.window(START, START + timedelta(minutes=60))
        assert [a.id for a in window] == ["a1", "a2"] and window[0].entity_keys() == {"host:h1"}
        assert [a.id for a in store.get_many(["a3", "a1", "zzz"])] == ["a1", "a3"]
        assert store.get_many([]) == []

    def test_incident_upsert_preserves_status_and_assignee(self, tmp_path: Path) -> None:
        incidents = IncidentStore(Database(tmp_path / "i.db"))
        incident = _incident(
            [make_alert("a1", 0, hosts=["ws-042"], techniques=["T1059.001"], severity="high")]
        )
        assert incidents.upsert(incident).status == "open"
        incidents.update_status(incident.id, "investigating", "carol")
        again = incidents.upsert(incident.model_copy(update={"risk_score": 99}))
        assert again.status == "investigating" and again.assignee == "carol"
        assert again.risk_score == 99
        assert incidents.update_status(incident.id, "contained").assignee == "carol"
        assert [i.id for i in incidents.list("contained")] == [incident.id]
        assert incidents.list("open") == []
        assert incidents.resolve_prefix(incident.id[:6]).id == incident.id
        with pytest.raises(StoreError):
            incidents.resolve_prefix("INC-nothing")
        with pytest.raises(StoreError):
            incidents.update_status("INC-nothing", "closed")

    def test_ambiguous_prefix(self, tmp_path: Path) -> None:
        incidents = IncidentStore(Database(tmp_path / "p.db"))
        for n in range(2):
            incidents.upsert(_incident([make_alert(f"x{n}", n, hosts=[f"h{n}"], severity="high")]))
        with pytest.raises(StoreError, match="incidents match"):
            incidents.resolve_prefix("INC-")

    def test_nested_transactions_commit_once_and_roll_back_together(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "t.db")
        audit = AuditLog(db)
        with db.transaction():
            audit.append("a", "one", "s")
            with db.transaction():
                audit.append("a", "two", "s")
        assert len(audit.entries()) == 2
        with pytest.raises(RuntimeError), db.transaction():
            audit.append("a", "three", "s")
            with db.transaction():
                audit.append("a", "four", "s")
            raise RuntimeError("boom")
        assert [e.action for e in audit.entries()] == ["one", "two"]

    def test_close_is_idempotent_and_context_manager(self, tmp_path: Path) -> None:
        with Database(tmp_path / "c.db") as db:
            db.conn.execute("SELECT 1")
        db.close()
        with pytest.raises(sqlite3.ProgrammingError):
            db.conn.execute("SELECT 1")

    def test_audit_chain_detects_tampering(self, tmp_path: Path) -> None:
        db = Database(tmp_path / "a.db")
        audit = AuditLog(db, lambda: NOW)
        for n in range(4):
            audit.append("alice", "act", f"s{n}", f"detail {n}")
        assert audit.verify() == (True, "")
        assert len(audit.entries(2)) == 2
        db.conn.execute("UPDATE audit_log SET detail='edited' WHERE id=2")
        db.conn.commit()
        ok, reason = audit.verify()
        assert not ok and "entry 2" in reason
        db.conn.execute("UPDATE audit_log SET detail='detail 1' WHERE id=2")
        db.conn.execute("DELETE FROM audit_log WHERE id=3")
        db.conn.commit()
        ok, reason = audit.verify()
        assert not ok and "entry 4" in reason

    def test_action_store_roundtrip(self, tmp_path: Path) -> None:
        actions = ActionStore(Database(tmp_path / "x.db"))
        alerts = [
            make_alert(
                "a1",
                0,
                hosts=["ws-042"],
                techniques=["T1059.001"],
                severity="critical",
                title="Encoded PowerShell",
            )
        ]
        incident = _incident(alerts)
        proposals = ContainmentAgent(Context(), Policy(), lambda: NOW).recommend(incident, alerts)
        assert proposals
        for p in proposals:
            actions.save(p)
        assert actions.get(proposals[0].id) == proposals[0] and actions.get("ACT-none") is None
        assert len(actions.for_incident(incident.id)) == len(proposals)
        assert actions.all("executed") == []
        with pytest.raises(StoreError):
            actions.resolve_prefix("ACT-none")


class TestCorrelation:
    def test_shared_entity_links_and_window_splits(self) -> None:
        agent = CorrelationAgent(Policy(correlation_window_minutes=60))
        groups = agent.correlate(
            [
                make_alert("a1", 0, hosts=["h1"]),
                make_alert("a2", 30, hosts=["h1"], users=["u1"]),
                make_alert("a3", 80, users=["u1"]),
                make_alert("a4", 500, hosts=["h1"]),
                make_alert("a5", 5, hosts=["other"]),
            ]
        )
        assert [[a.id for a in g] for g in groups] == [["a1", "a2", "a3"], ["a5"], ["a4"]]

    def test_hub_entities_do_not_merge_unrelated_alerts(self) -> None:
        agent = CorrelationAgent(Policy(max_entity_degree=3))
        alerts = [make_alert(f"n{n}", n, ips=["198.18.0.1"], hosts=[f"h{n}"]) for n in range(5)]
        assert agent.hubs(alerts) == {"ip:198.18.0.1"} and len(agent.correlate(alerts)) == 5

    def test_noise_entities_are_ignored(self) -> None:
        agent = CorrelationAgent(Policy())
        alerts = [
            make_alert("a1", 0, users=["SYSTEM"]),
            make_alert("a2", 1, users=["system"], ips=["127.0.0.1"]),
            make_alert("a3", 2, ips=["127.0.0.1"]),
        ]
        assert len(agent.correlate(alerts)) == 3

    def test_incident_id_is_stable_under_reordering_and_growth(self) -> None:
        a, b, c = make_alert("a1", 0), make_alert("a2", 5), make_alert("a3", 9)
        assert incident_id_for([a, b]) == incident_id_for([b, a]) == incident_id_for([a, b, c])
        assert incident_id_for([a]).startswith("INC-") and incident_id_for([b]) != incident_id_for(
            [a]
        )

    def test_empty_input(self) -> None:
        assert CorrelationAgent(Policy()).correlate([]) == []


def _intrusion() -> list[Alert]:
    return [
        make_alert(
            "m1",
            0,
            title="Phishing attachment opened",
            severity="high",
            hosts=["ws-042"],
            users=["alice"],
            techniques=["T1566.001"],
            domains=["evil.example"],
        ),
        make_alert(
            "m2",
            5,
            title="Encoded PowerShell",
            severity="high",
            hosts=["ws-042"],
            users=["alice"],
            techniques=["T1059.001"],
            hashes=[HASH],
        ),
        make_alert(
            "m3",
            10,
            title="Beaconing to C2",
            severity="critical",
            hosts=["ws-042"],
            ips=["203.0.113.66"],
            techniques=["T1071"],
        ),
        make_alert(
            "m4",
            30,
            title="RDP to file server",
            severity="high",
            hosts=["ws-042", "srv-file01"],
            users=["alice"],
            techniques=["T1021.001"],
        ),
    ]


def _context(tmp_path: Path) -> Context:
    o = write_configs(
        tmp_path,
        assets=[
            {"name": "ws-042", "criticality": "medium", "owner": "alice"},
            {"name": "srv-file01", "criticality": "critical", "owner": "it-storage"},
            {"name": "dc01", "criticality": "critical"},
        ],
        identities=[
            {"name": "svc-backup", "service_account": True},
            {"name": "admin.jsmith", "privileged": True},
        ],
        indicators=[
            {"type": "ip", "value": "203.0.113.66", "confidence": 90},
            {"type": "hash", "value": HASH},
        ],
    )
    return load_context(o["assets_file"], o["iocs_file"])  # type: ignore[arg-type]


class TestInvestigation:
    def test_intrusion_is_p1_with_expected_hypotheses(self, tmp_path: Path) -> None:
        alerts = _intrusion()
        incident = _incident(alerts, _context(tmp_path))
        names = {h.name for h in incident.investigation.hypotheses}
        assert {"malware_execution", "phishing_initial_access", "lateral_movement"} <= names
        assert incident.priority == "P1" and incident.risk_score >= 85
        assert incident.title.endswith("ws-042")
        inv = incident.investigation
        assert {m.entity for m in inv.ioc_matches} == {"ip:203.0.113.66", "hash:" + HASH}
        assert "srv-file01" in inv.critical_assets
        assert [t.alert_id for t in inv.timeline] == ["m1", "m2", "m3", "m4"]
        assert incident.first_seen == START
        assert incident.last_seen == START + timedelta(minutes=30)
        assert incident.score_factors

    def test_single_low_alert_is_low_priority(self) -> None:
        incident = _incident(
            [make_alert("s1", 0, title="Unusual DNS query", severity="low", hosts=["h1"])]
        )
        assert incident.priority == "P4" and incident.investigation.hypotheses == []

    def test_password_spray_then_success_is_credential_compromise(self) -> None:
        alerts = [
            make_alert(
                f"f{n}",
                n,
                title="Failed logon",
                severity="low",
                users=["bob"],
                ips=["198.51.100.23"],
                techniques=["T1110"],
                description="Failed logon attempt",
            )
            for n in range(6)
        ]
        alerts.append(
            make_alert(
                "s",
                8,
                title="Successful logon after failures",
                severity="medium",
                users=["bob"],
                ips=["198.51.100.23"],
                techniques=["T1078"],
                description="Logon success",
            )
        )
        incident = _incident(alerts)
        assert "credential_compromise" in {h.name for h in incident.investigation.hypotheses}
        assert incident.priority in {"P1", "P2", "P3"}

    def test_privileged_user_raises_score(self, tmp_path: Path) -> None:
        agent = InvestigationAgent(_context(tmp_path), Policy())
        plain = [make_alert("p1", 0, severity="medium", users=["alice"], techniques=["T1078"])]
        admin = [
            make_alert("p1", 0, severity="medium", users=["admin.jsmith"], techniques=["T1078"])
        ]
        assert (
            agent.build_incident("INC-1", admin).risk_score
            > agent.build_incident("INC-1", plain).risk_score
        )

    def test_deterministic(self, tmp_path: Path) -> None:
        agent = InvestigationAgent(_context(tmp_path), Policy())
        assert agent.build_incident("INC-1", _intrusion()) == agent.build_incident(
            "INC-1", list(reversed(_intrusion()))
        )


class TestContainment:
    def _plan(self, tmp_path: Path, policy: Policy | None = None) -> dict[tuple[str, str], Any]:
        policy = policy or Policy(senior_approvers=["lead"], approvers=["ana"])
        alerts = _intrusion()
        ctx = _context(tmp_path)
        incident = InvestigationAgent(ctx, policy).build_incident("INC-1", alerts)
        agent = ContainmentAgent(ctx, policy, lambda: NOW)
        return {(a.type, a.target): a for a in agent.recommend(incident, alerts)}

    def test_expected_proposals(self, tmp_path: Path) -> None:
        plan = self._plan(tmp_path)
        expected = {
            ("snapshot_host", "ws-042"),
            ("isolate_host", "ws-042"),
            ("block_ip", "203.0.113.66"),
            ("block_hash", HASH),
            ("open_ticket", "INC-1"),
            ("disable_user", "alice"),
        }
        assert expected <= set(plan)

    def test_isolate_depends_on_snapshot_and_critical_asset_needs_senior(
        self, tmp_path: Path
    ) -> None:
        plan = self._plan(tmp_path)
        isolate = plan[("isolate_host", "ws-042")]
        assert isolate.depends_on == [action_id("INC-1", "snapshot_host", "ws-042")]
        assert not isolate.requires_senior
        critical = plan[("isolate_host", "srv-file01")]
        assert critical.requires_senior and critical.impact == "high" and critical.warnings

    def test_internal_addresses_are_never_blocked(self) -> None:
        alerts = [
            make_alert(
                "x",
                0,
                severity="critical",
                hosts=["h1"],
                ips=["10.0.0.5"],
                techniques=["T1059.001", "T1071"],
            )
        ]
        incident = _incident(alerts)
        proposals = ContainmentAgent(Context(), Policy()).recommend(incident, alerts)
        assert not [a for a in proposals if a.type == "block_ip"]

    def test_protected_targets_become_manual_only(self, tmp_path: Path) -> None:
        policy = Policy(
            protected_hosts=["ws-042"], protected_users=["alice"], senior_approvers=["lead"]
        )
        plan = self._plan(tmp_path, policy)
        assert plan[("isolate_host", "ws-042")].status == "manual_only"
        assert plan[("disable_user", "alice")].status == "manual_only"
        assert plan[("block_ip", "203.0.113.66")].status == "pending_approval"

    def test_action_ids_are_stable_and_distinct(self) -> None:
        assert action_id("I", "isolate_host", "h") == action_id("I", "isolate_host", "h")
        ids = {
            action_id("I", "isolate_host", "h"),
            action_id("I", "snapshot_host", "h"),
            action_id("J", "snapshot_host", "h"),
        }
        assert len(ids) == 3

    def test_service_accounts_need_senior_approval(self) -> None:
        ctx = Context.model_validate(
            {"identities": {"svc-backup": {"name": "svc-backup", "service_account": True}}}
        )
        alerts = [
            make_alert(
                "c",
                0,
                severity="high",
                users=["svc-backup"],
                techniques=["T1110"],
                title="Failed logon",
                description="Failed logon",
            ),
            make_alert(
                "d",
                1,
                severity="high",
                users=["svc-backup"],
                techniques=["T1078"],
                title="Logon success",
                description="Logon success",
            ),
        ]
        incident = InvestigationAgent(ctx, Policy()).build_incident("INC-3", alerts)
        proposals = ContainmentAgent(ctx, Policy()).recommend(incident, alerts)
        disables = [a for a in proposals if a.type == "disable_user"]
        assert disables and all(a.requires_senior for a in disables)


class _LLM:
    def __init__(self, reply: str | Exception) -> None:
        self.reply = reply
        self.seen: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.seen.append(user)
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class TestSummary:
    def _facts(self, tmp_path: Path) -> tuple[Incident, SummaryFacts]:
        incident = InvestigationAgent(_context(tmp_path), Policy()).build_incident(
            "INC-1", _intrusion()
        )
        return incident, facts_for(incident, [])

    def test_template_mentions_key_numbers(self, tmp_path: Path) -> None:
        incident, facts = self._facts(tmp_path)
        text = TemplateSummaryWriter().write(facts)
        assert f"{incident.priority} incident" in text and "4 alerts" in text
        assert "awaiting human approval" in text

    def test_facts_hold_no_raw_entities_or_titles(self, tmp_path: Path) -> None:
        _, facts = self._facts(tmp_path)
        payload = facts.model_dump_json()
        assert "ws-042" not in payload and "alice" not in payload
        assert "Encoded PowerShell" not in payload

    def test_llm_output_used_when_grounded_and_only_sees_facts(self, tmp_path: Path) -> None:
        _, facts = self._facts(tmp_path)
        llm = _LLM(f"A {facts.priority} incident with {facts.alerts} alerts.")
        assert LLMSummaryWriter(llm).write(facts).startswith("A P1")
        assert "ws-042" not in llm.seen[0]

    @pytest.mark.parametrize(
        "reply", ["We saw 4711 alerts.", "", "x" * 2000, ProviderError("down")]
    )
    def test_bad_llm_output_falls_back(self, tmp_path: Path, reply: str | Exception) -> None:
        _, facts = self._facts(tmp_path)
        assert LLMSummaryWriter(_LLM(reply)).write(facts) == TemplateSummaryWriter().write(facts)
