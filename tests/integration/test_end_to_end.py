"""End-to-end tests: multi-vendor ingest, triage, approval, execution, audit, CLI and connectors."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from socagent.cli import main
from socagent.container import build_service
from socagent.errors import ActionError, ConfigurationError, SocagentError
from socagent.executor import DryRunConnector, WebhookConnector
from socagent.models import Action
from socagent.reporting import render, write_report
from socagent.service import IRService, parse_duration
from socagent.simulate import C2_IP, MALWARE_SHA256, simulate, write_records
from tests.conftest import CONFIGS, NOW, START, json_client, make_service, make_settings

DAY = parse_duration("24h")


class Clock:
    def __init__(self, moment: datetime) -> None:
        self.moment = moment

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs: float) -> None:
        self.moment += timedelta(**kwargs)


def load_scenario(service: IRService, directory: Path) -> None:
    for path in write_records(simulate(start=START), directory):
        service.ingest_file(path.stem, path)


def triaged(tmp_path: Path, clock: Clock | None = None, **overrides: object) -> IRService:
    service = make_service(tmp_path, clock=clock or Clock(NOW), **overrides)
    load_scenario(service, tmp_path / "feeds")
    service.triage(lookback=DAY, now=NOW)
    return service


def find(service: IRService, kind: str, target: str) -> Action:
    for action in service.actions.all():
        if action.type == kind and action.target == target:
            return action
    raise AssertionError(f"no {kind} action for {target}")


class TestTriage:
    def test_scenario_produces_the_expected_incidents(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        load_scenario(service, tmp_path / "feeds")
        result = service.triage(lookback=DAY, now=NOW)
        assert result.alerts_considered == 48 and len(result.incidents) == 3
        by_title = {i.title: i for i in result.incidents}
        main_incident = by_title["Malware execution with command and control: ws-042"]
        assert main_incident.priority == "P1" and len(main_incident.alert_ids) == 6
        assert len(main_incident.sources) == 4
        assert any(
            t.startswith("Credential compromise") and i.priority in {"P1", "P2"}
            for t, i in by_title.items()
        )
        assert result.details["suppressed_singletons"] == 30
        assert not any("198.18.0.1" in i.title for i in result.incidents)

    def test_triage_is_idempotent_and_keeps_human_status(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        first = {i.id: i for i in service.incidents.list()}
        incident = next(iter(first.values()))
        service.set_status(incident.id, "investigating", "carol", "carol")
        again = service.triage(lookback=DAY, now=NOW)
        assert again.new_actions == 0 and {i.id for i in again.incidents} == set(first)
        assert service.incidents.get(incident.id).status == "investigating"  # type: ignore[union-attr]

    def test_reingest_reports_duplicates(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        path = tmp_path / "feeds" / "splunk.jsonl"
        report = service.ingest_file("splunk", path)
        assert report.accepted == 0 and report.duplicates > 0 and report.rejected == 0

    def test_new_alerts_merge_incidents_and_close_the_old_one(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        rows = [
            {
                "id": "g1",
                "timestamp": "2026-09-19T06:00:00Z",
                "title": "Odd process",
                "severity": "high",
                "entities": [{"type": "host", "value": "h1"}],
            },
            {
                "id": "g2",
                "timestamp": "2026-09-19T09:00:00Z",
                "title": "Odd logon",
                "severity": "high",
                "entities": [{"type": "user", "value": "zed"}],
            },
        ]
        feed = tmp_path / "g.jsonl"
        feed.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        service.ingest_file("generic", feed)
        assert len(service.triage(lookback=DAY, now=NOW).incidents) == 2
        bridge = {
            "id": "g3",
            "timestamp": "2026-09-19T07:30:00Z",
            "title": "Odd bridge",
            "severity": "high",
            "entities": [{"type": "host", "value": "h1"}, {"type": "user", "value": "zed"}],
        }
        feed.write_text(json.dumps(bridge) + "\n", encoding="utf-8")
        service.ingest_file("generic", feed)
        result = service.triage(lookback=DAY, now=NOW)
        assert len(result.incidents) == 1 and result.details["closed_as_merged"] == 1
        statuses = sorted(i.status for i in service.incidents.list())
        assert statuses == ["closed", "open"]
        assert any(e.action == "incident.merged" for e in service.audit.entries())

    def test_lookback_limits_alerts(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        load_scenario(service, tmp_path / "feeds")
        assert service.triage(lookback=parse_duration("30m"), now=NOW).alerts_considered == 0

    def test_secrets_in_command_lines_never_reach_storage_or_reports(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        row = {
            "result": {
                "_time": "2026-09-19T06:00:00Z",
                "rule_name": "Suspicious process",
                "urgency": "high",
                "src_host": "ws-1",
                "process": "tool.exe -password hunter2xyz --token abc12345",
            }
        }
        feed = tmp_path / "s.jsonl"
        feed.write_text(json.dumps(row) + "\n", encoding="utf-8")
        service.ingest_file("splunk", feed)
        service.triage(lookback=DAY, now=NOW)
        incident = service.incidents.list()[0]
        incident, actions = service.get_incident(incident.id)
        blob = render(incident, actions, "md") + render(incident, actions, "json")
        dump = "".join(str(r) for r in service.db.conn.iterdump())
        assert "hunter2xyz" not in blob + dump and "abc12345" not in blob + dump


class TestIngestRobustness:
    def test_bad_lines_are_counted_without_echoing_content(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        feed = tmp_path / "bad.jsonl"
        feed.write_text(
            "not json password=Sup3rSecret\n[1,2]\n"
            + json.dumps({"result": {"rule_name": "no time"}})
            + "\n"
            + json.dumps(
                {"result": {"_time": "2026-09-19T06:00:00Z", "rule_name": "ok", "dest": "h1"}}
            )
            + "\n\n",
            encoding="utf-8",
        )
        report = service.ingest_file("splunk", feed)
        assert report.accepted == 1 and report.rejected == 3
        assert "Sup3rSecret" not in report.model_dump_json()

    def test_oversized_lines_are_rejected(self, tmp_path: Path) -> None:
        service = make_service(tmp_path, max_line_bytes=1000)
        good = json.dumps(
            {"result": {"_time": "2026-09-19T06:00:00Z", "rule_name": "r", "dest": "h1"}}
        )
        feed = tmp_path / "big.jsonl"
        feed.write_text("x" * 2000 + "\n" + good + "\n", encoding="utf-8")
        report = service.ingest_file("splunk", feed)
        assert report.rejected == 1 and report.accepted == 1

    def test_line_limit_aborts_the_import(self, tmp_path: Path) -> None:
        service = make_service(tmp_path, max_lines=3)
        good = json.dumps(
            {"result": {"_time": "2026-09-19T06:00:00Z", "rule_name": "r", "dest": "h1"}}
        )
        feed = tmp_path / "many.jsonl"
        feed.write_text((good + "\n") * 6, encoding="utf-8")
        with pytest.raises(SocagentError, match="limit"):
            service.ingest_file("splunk", feed)

    def test_missing_file_is_a_domain_error(self, tmp_path: Path) -> None:
        with pytest.raises(SocagentError):
            make_service(tmp_path).ingest_file("splunk", tmp_path / "absent.jsonl")

    def test_unknown_source_is_rejected(self, tmp_path: Path) -> None:
        feed = tmp_path / "f.jsonl"
        feed.write_text("{}\n", encoding="utf-8")
        with pytest.raises(SocagentError):
            make_service(tmp_path).ingest_file("carrier-pigeon", feed)


class TestApprovalWorkflow:
    def test_full_lifecycle_with_dependency_order_and_audit(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        actions = service.action_service
        snapshot, isolate = (
            find(service, "snapshot_host", "ws-042"),
            find(service, "isolate_host", "ws-042"),
        )
        assert isolate.depends_on == [snapshot.id] and isolate.status == "pending_approval"

        with pytest.raises(ActionError, match="must be approved"):
            actions.execute(isolate.id, "soc-analyst-1")
        actions.approve(isolate.id, "soc-analyst-1")
        with pytest.raises(ActionError, match="depends on"):
            actions.execute(isolate.id, "soc-analyst-1")
        actions.approve(snapshot.id, "soc-analyst-1")
        done = actions.execute(snapshot.id, "soc-analyst-1")
        assert done.status == "executed" and done.result.startswith("dry run")
        assert actions.execute(isolate.id, "soc-analyst-1").status == "executed"
        with pytest.raises(ActionError, match="must be approved"):
            actions.execute(isolate.id, "soc-analyst-1")
        assert service.audit.verify() == (True, "")
        names = [e.action for e in service.audit.entries()]
        for expected in (
            "action.propose",
            "action.approve",
            "action.execute.start",
            "action.execute.done",
        ):
            assert expected in names

    def test_unknown_and_blank_identities_are_refused(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        target = find(service, "block_ip", C2_IP)
        with pytest.raises(ActionError, match="not an authorised approver"):
            service.action_service.approve(target.id, "mallory")
        with pytest.raises(ActionError, match="approver name"):
            service.action_service.approve(target.id, "  ")
        with pytest.raises(ActionError, match="not found"):
            service.action_service.approve("ACT-missing", "soc-analyst-1")
        assert service.actions.get(target.id).status == "pending_approval"  # type: ignore[union-attr]

    def test_critical_asset_actions_need_a_senior_approver(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        critical = find(service, "isolate_host", "srv-file01")
        assert critical.requires_senior
        with pytest.raises(ActionError, match="senior"):
            service.action_service.approve(critical.id, "soc-analyst-1")
        assert service.action_service.approve(critical.id, "soc-lead").approved_by == "soc-lead"

    def test_protected_targets_cannot_be_approved(self, tmp_path: Path) -> None:
        overrides = {"policy_file": _policy(tmp_path, protected_hosts=["ws-042"])}
        service = triaged(tmp_path, **overrides)
        blocked = find(service, "isolate_host", "ws-042")
        assert blocked.status == "manual_only"
        with pytest.raises(ActionError, match="protected"):
            service.action_service.approve(blocked.id, "soc-analyst-1")

    def test_target_protected_after_approval_is_blocked_at_execution(self, tmp_path: Path) -> None:
        clock = Clock(NOW)
        service = triaged(tmp_path, clock)
        target = find(service, "block_ip", C2_IP)
        service.action_service.approve(target.id, "soc-analyst-1")
        service.action_service._policy.protected_ips.append(C2_IP)
        with pytest.raises(ActionError, match="protected"):
            service.action_service.execute(target.id, "soc-analyst-1")
        assert service.actions.get(target.id).status == "manual_only"  # type: ignore[union-attr]

    def test_stale_approval_expires(self, tmp_path: Path) -> None:
        clock = Clock(NOW)
        service = triaged(tmp_path, clock)
        target = (
            find(service, "block_domain", "evil-cdn.example")
            if _has(service, "block_domain")
            else find(service, "block_ip", C2_IP)
        )
        service.action_service.approve(target.id, "soc-analyst-1")
        clock.advance(minutes=service.policy.approval_ttl_minutes + 1)
        with pytest.raises(ActionError, match="expired"):
            service.action_service.execute(target.id, "soc-analyst-1")
        assert service.actions.get(target.id).status == "expired"  # type: ignore[union-attr]
        with pytest.raises(ActionError, match="expired"):
            service.action_service.approve(target.id, "soc-analyst-1")

    def test_reject_records_reason_and_blocks_execution(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        target = find(service, "block_ip", C2_IP)
        rejected = service.action_service.reject(target.id, "soc-analyst-2", "false positive")
        assert rejected.status == "rejected" and rejected.result == "false positive"
        with pytest.raises(ActionError):
            service.action_service.execute(target.id, "soc-analyst-2")
        with pytest.raises(ActionError, match="cannot be rejected"):
            service.action_service.reject(target.id, "soc-analyst-2", "again")

    def test_approval_survives_retriage_and_actions_are_not_duplicated(
        self, tmp_path: Path
    ) -> None:
        service = triaged(tmp_path)
        target = find(service, "block_ip", C2_IP)
        service.action_service.approve(target.id, "soc-analyst-1")
        count = len(service.actions.all())
        service.triage(lookback=DAY, now=NOW)
        assert len(service.actions.all()) == count
        after = service.actions.get(target.id)
        assert (
            after is not None
            and after.status == "approved"
            and after.approved_by == "soc-analyst-1"
        )

    def test_tampering_with_the_audit_log_is_detected(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        service.db.conn.execute("UPDATE audit_log SET actor='someone-else' WHERE id=3")
        service.db.conn.commit()
        ok, reason = service.audit.verify()
        assert not ok and "entry 3" in reason


def _has(service: IRService, kind: str) -> bool:
    return any(a.type == kind for a in service.actions.all())


def _policy(tmp_path: Path, **extra: object) -> Path:
    import yaml

    base = yaml.safe_load((CONFIGS / "policy.example.yaml").read_text(encoding="utf-8"))
    base.update(extra)
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(base), encoding="utf-8")
    return path


class TestConnectors:
    def test_webhook_receives_the_approved_action_and_secret_url_is_hidden(
        self, tmp_path: Path
    ) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"ok": True})

        settings = make_settings(
            tmp_path,
            assets_file=CONFIGS / "assets.example.yaml",
            iocs_file=CONFIGS / "iocs.example.json",
            policy_file=CONFIGS / "policy.example.yaml",
            execution_mode="live",
            connector_url=SecretStr("https://soar.example/hooks/s3cr3t-token"),
        )
        service = build_service(
            settings,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
            clock=lambda: NOW,
        )
        load_scenario(service, tmp_path / "feeds")
        service.triage(lookback=DAY, now=NOW)
        target = find(service, "block_ip", C2_IP)
        service.action_service.approve(target.id, "soc-analyst-1")
        done = service.action_service.execute(target.id, "soc-analyst-2")
        assert done.status == "executed" and done.result.startswith("sent to connector")
        body = json.loads(seen[0].content)
        assert body["action"] == "block_ip" and body["target"] == C2_IP
        assert body["approved_by"] == "soc-analyst-1" and body["executed_by"] == "soc-analyst-2"
        detail = " ".join(e.detail for e in service.audit.entries())
        assert "s3cr3t-token" not in detail and "s3cr3t-token" not in done.result

    def test_connector_failure_marks_the_action_failed_and_is_audited(self, tmp_path: Path) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="boom")

        connector = WebhookConnector(json_client(handler), SecretStr("https://soar.example/hook"))
        service = (
            triaged(tmp_path, clock=None)
            if False
            else make_service(
                tmp_path,
                clock=lambda: NOW,
            )
        )
        service = build_service(
            make_settings(
                tmp_path,
                assets_file=CONFIGS / "assets.example.yaml",
                iocs_file=CONFIGS / "iocs.example.json",
                policy_file=CONFIGS / "policy.example.yaml",
                db_path=tmp_path / "f.db",
            ),
            connector=connector,
            clock=lambda: NOW,
        )
        load_scenario(service, tmp_path / "feeds")
        service.triage(lookback=DAY, now=NOW)
        target = find(service, "block_ip", C2_IP)
        service.action_service.approve(target.id, "soc-analyst-1")
        with pytest.raises(ActionError, match="connector failed"):
            service.action_service.execute(target.id, "soc-analyst-1")
        assert service.actions.get(target.id).status == "failed"  # type: ignore[union-attr]
        assert "action.execute.failed" in [e.action for e in service.audit.entries()]
        assert service.audit.verify() == (True, "")

    def test_dry_run_is_the_default_connector(self, tmp_path: Path) -> None:
        assert isinstance(DryRunConnector(), DryRunConnector)
        service = triaged(tmp_path)
        assert service.settings.execution_mode == "dry_run"

    def test_live_mode_without_url_is_a_configuration_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="CONNECTOR_URL"):
            make_settings(tmp_path, execution_mode="live")


class TestReporting:
    def test_markdown_and_json(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        incident = service.incidents.list()[0]
        incident, actions = service.get_incident(incident.id)
        md = render(incident, actions, "md")
        assert incident.id in md and "## Notice" in md and "Timeline" in md
        payload = json.loads(render(incident, actions, "json"))
        assert payload["incident"]["id"] == incident.id and len(payload["actions"]) == len(actions)
        with pytest.raises(SocagentError, match="unknown format"):
            render(incident, actions, "pdf")
        paths = write_report(incident, actions, tmp_path / "out", ["md", "json"])
        assert [p.name for p in paths] == [f"{incident.id}.md", f"{incident.id}.json"]

    def test_hostile_titles_cannot_break_out_of_tables(self, tmp_path: Path) -> None:
        service = make_service(tmp_path)
        row = {
            "id": "h1",
            "timestamp": "2026-09-19T06:00:00Z",
            "severity": "high",
            "title": "evil | <script>alert(1)</script>\n# injected",
            "entities": [{"type": "host", "value": "h1"}],
        }
        feed = tmp_path / "h.jsonl"
        feed.write_text(json.dumps(row) + "\n", encoding="utf-8")
        service.ingest_file("generic", feed)
        service.triage(lookback=DAY, now=NOW)
        incident, actions = service.get_incident(service.incidents.list()[0].id)
        md = render(incident, actions, "md")
        assert "\n# injected" not in md and "<script>" not in md

    def test_unwritable_output_directory(self, tmp_path: Path) -> None:
        service = triaged(tmp_path)
        incident, actions = service.get_incident(service.incidents.list()[0].id)
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(SocagentError):
            write_report(incident, actions, blocker / "sub", ["md"])


class TestSimulation:
    def test_is_deterministic_and_covers_every_vendor(self) -> None:
        a, b = simulate(start=START), simulate(start=START)
        assert a == b and set(a) == {"splunk", "sentinel", "crowdstrike", "elastic"}
        assert simulate(start=START, seed=8) != a
        assert len(simulate(start=START, noise=0)["splunk"]) < len(a["splunk"])
        assert MALWARE_SHA256 in json.dumps(a)


class TestCli:
    @pytest.fixture
    def env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        monkeypatch.delenv("SOCAGENT_EXECUTION_MODE", raising=False)
        monkeypatch.setenv("SOCAGENT_DB_PATH", str(tmp_path / "cli.db"))
        monkeypatch.setenv("SOCAGENT_ASSETS_FILE", str(CONFIGS / "assets.example.yaml"))
        monkeypatch.setenv("SOCAGENT_IOCS_FILE", str(CONFIGS / "iocs.example.json"))
        monkeypatch.setenv("SOCAGENT_POLICY_FILE", str(CONFIGS / "policy.example.yaml"))
        monkeypatch.setenv("SOCAGENT_LOG_LEVEL", "CRITICAL")
        monkeypatch.chdir(tmp_path)
        return tmp_path

    def test_full_workflow(self, env: Path, capsys: pytest.CaptureFixture[str]) -> None:
        feeds = env / "feeds"
        assert main(["simulate", "--out", str(feeds), "--start", "2026-09-19T06:00:00Z"]) == 0
        for source in ("splunk", "sentinel", "crowdstrike", "elastic"):
            assert main(["ingest", "--source", source, str(feeds / f"{source}.jsonl")]) == 0
        capsys.readouterr()
        assert main(["triage", "--now", "2026-09-19T14:00:00Z", "--fail-on", "P1"]) == 1
        out = capsys.readouterr().out
        assert "3 incidents" in out and "P1" in out
        assert main(["triage", "--now", "2026-09-19T14:00:00Z"]) == 0
        capsys.readouterr()

        assert main(["incidents", "list", "--status", "open"]) == 0
        listing = capsys.readouterr().out
        incident_id = next(line.split()[0] for line in listing.splitlines() if "ws-042" in line)
        assert (
            main(
                [
                    "incidents",
                    "show",
                    incident_id[:8],
                    "--format",
                    "md,json",
                    "--out",
                    str(env / "reports"),
                ]
            )
            == 0
        )
        assert (env / "reports" / f"{incident_id}.md").exists()
        assert main(["incidents", "show", incident_id]) == 0
        assert "Notice" in capsys.readouterr().out
        assert (
            main(
                [
                    "incidents",
                    "status",
                    incident_id,
                    "investigating",
                    "--actor",
                    "soc-analyst-1",
                    "--assignee",
                    "soc-analyst-1",
                ]
            )
            == 0
        )

        assert main(["actions", "list", "--incident", incident_id]) == 0
        rows = capsys.readouterr().out.splitlines()
        snapshot = next(r.split()[0] for r in rows if "snapshot_host ws-042" in r)
        isolate = next(r.split()[0] for r in rows if "isolate_host ws-042" in r)
        assert main(["actions", "execute", isolate, "--executor", "soc-analyst-1"]) == 2
        assert "must be approved" in capsys.readouterr().err
        assert main(["actions", "approve", snapshot, "--approver", "soc-analyst-1"]) == 0
        assert main(["actions", "approve", isolate, "--approver", "soc-analyst-1"]) == 0
        assert main(["actions", "execute", isolate, "--executor", "soc-analyst-1"]) == 2
        assert "depends on" in capsys.readouterr().err
        assert main(["actions", "execute", snapshot, "--executor", "soc-analyst-1"]) == 0
        assert main(["actions", "execute", isolate, "--executor", "soc-analyst-1"]) == 0
        assert "dry run" in capsys.readouterr().out
        assert (
            main(["actions", "reject", snapshot, "--approver", "soc-analyst-1", "--reason", "x"])
            == 2
        )
        capsys.readouterr()
        assert main(["actions", "list", "--status", "executed"]) == 0
        assert main(["audit", "--limit", "5"]) == 0
        assert main(["audit", "--verify"]) == 0
        assert "chain intact" in capsys.readouterr().out

    def test_errors_exit_two_without_leaking_secrets(
        self, env: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["ingest", "--source", "splunk", str(env / "missing.jsonl")]) == 2
        assert main(["triage", "--lookback", "soon"]) == 2
        assert main(["triage", "--now", "yesterday"]) == 2
        assert main(["incidents", "show", "INC-none"]) == 2
        assert main(["actions", "approve", "ACT-none", "--approver", "x"]) == 2
        assert main(["simulate", "--out", str(env / "o"), "--start", "garbage"]) == 2
        assert "error:" in capsys.readouterr().err

    def test_actions_and_incidents_on_an_empty_database(
        self, env: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["incidents", "list"]) == 0 and "no incidents" in capsys.readouterr().out
        assert main(["actions", "list"]) == 0 and "no actions" in capsys.readouterr().out
        assert main(["audit", "--verify"]) == 0

    def test_audit_verify_fails_with_exit_one_when_tampered(
        self, env: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with build_service(make_settings(env, db_path=env / "cli.db")) as service:
            service.audit.append("a", "one", "s")
            service.audit.append("a", "two", "s")
            service.db.conn.execute("UPDATE audit_log SET detail='x' WHERE id=1")
            service.db.conn.commit()
        assert main(["audit", "--verify"]) == 1
        assert "TAMPERED" in capsys.readouterr().out

    def test_db_flag_overrides_environment(
        self, env: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        other = env / "other.db"
        assert main(["--db", str(other), "audit"]) == 0
        assert other.exists()

    def test_live_mode_without_connector_is_an_error(
        self, env: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("SOCAGENT_EXECUTION_MODE", "live")
        assert main(["audit"]) == 2
        assert "CONNECTOR_URL" in capsys.readouterr().err


def test_configuration_error_type_is_a_socagent_error() -> None:
    assert issubclass(ConfigurationError, SocagentError)
