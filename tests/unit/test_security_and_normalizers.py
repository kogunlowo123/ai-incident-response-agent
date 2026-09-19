"""Unit tests for redaction, observable normalisation, ATT&CK helpers and vendor normalisers."""

from __future__ import annotations

import json
from datetime import timezone

import pytest

from socagent import mitre
from socagent.models import Severity
from socagent.normalizers import (
    NORMALIZERS,
    NormalizeError,
    as_list,
    crowdstrike,
    dig,
    elastic,
    first,
    generic,
    map_severity,
    parse_time,
    sentinel,
    splunk,
)
from socagent.security import (
    is_private_ip,
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_host,
    normalize_ip,
    normalize_user,
    redact,
    url_domain,
)


class TestRedaction:
    @pytest.mark.parametrize(
        ("text", "secret"),
        [
            ("powershell.exe -password hunter2xyz -enc AAA", "hunter2xyz"),
            ("net use \\\\srv /user:bob --password=S3cretPass", "S3cretPass"),
            ("curl -H 'Authorization: Bearer abcdefghijklmnop1234'", "abcdefghijklmnop1234"),
            ("key = sk-" + "a" * 30, "a" * 30),
            ("token: " + "gh" + "p_" + "b" * 36, "b" * 36),
            ("AK" + "IA" + "C" * 16, "C" * 16),
            ("--token abc12345", "abc12345"),
        ],
    )
    def test_secrets_are_removed(self, text: str, secret: str) -> None:
        assert secret not in redact(text)

    def test_idempotent_and_plain_text_untouched(self) -> None:
        once = redact("cmd -password hunter2xyz")
        assert redact(once) == once and "[REDACTED]" in once
        assert redact("powershell.exe -enc SQBFAFgA") == "powershell.exe -enc SQBFAFgA"


class TestObservables:
    def test_ip(self) -> None:
        assert normalize_ip(" 203.0.113.66 ") == "203.0.113.66"
        assert normalize_ip("[2001:db8::1]") == "2001:db8::1"
        assert normalize_ip("999.1.1.1") is None and normalize_ip("host") is None

    @pytest.mark.parametrize(
        ("ip", "internal"),
        [
            ("10.1.2.3", True),
            ("172.16.5.5", True),
            ("172.32.0.1", False),
            ("192.168.1.1", True),
            ("127.0.0.1", True),
            ("169.254.1.1", True),
            ("::1", True),
            ("fc00::1", True),
            ("fe80::1", True),
            ("203.0.113.66", False),
            ("198.51.100.23", False),
            ("8.8.8.8", False),
            ("2001:db8::1", False),
            ("nonsense", False),
        ],
    )
    def test_internal_address_detection(self, ip: str, internal: bool) -> None:
        assert is_private_ip(ip) is internal

    def test_hash(self) -> None:
        digest = "A" * 64
        assert (
            normalize_hash(digest) == "a" * 64
            and normalize_hash("b" * 32)
            and normalize_hash("c" * 40)
        )
        assert (
            normalize_hash("xyz") is None
            and normalize_hash("g" * 64) is None
            and normalize_hash("a" * 30) is None
        )

    def test_domain_host_email_url(self) -> None:
        assert normalize_domain("Evil-CDN.Example.") == "evil-cdn.example"
        assert normalize_domain("not a domain") is None and normalize_domain("localhost") is None
        assert normalize_host("WS-042") == "ws-042" and normalize_host("bad host!") is None
        assert (
            normalize_email("Billing@Evil.Example") == "billing@evil.example"
            and normalize_email("nope") is None
        )
        assert url_domain("https://Evil.example/path?q=1") == "evil.example"
        assert (
            url_domain("evil.example/x") == "evil.example"
            and url_domain("http://10.0.0.1/") is None
        )

    @pytest.mark.parametrize(
        "raw", ["alice", "ALICE", "CORP\\alice", "alice@corp.example", "Corp\\Alice"]
    )
    def test_user_forms_converge(self, raw: str) -> None:
        assert normalize_user(raw) == "alice"

    def test_user_rejects_empty(self) -> None:
        assert normalize_user("   ") is None and normalize_user("CORP\\") is None


class TestMitre:
    def test_normalisation(self) -> None:
        assert (
            mitre.normalize_technique(" t1059.001 ") == "T1059.001"
            and mitre.normalize_technique("T12") is None
        )
        assert mitre.normalize_tactic("ta0002") == "TA0002"
        assert mitre.normalize_tactic("Lateral Movement") == "TA0008"
        assert mitre.normalize_tactic("lateral-movement") == "TA0008"
        assert mitre.normalize_tactic("Nonsense") is None

    def test_lookups(self) -> None:
        assert mitre.technique_name("T1059.001") == "PowerShell"
        assert mitre.technique_name("T1059.999") == "Command and Scripting Interpreter"
        assert mitre.technique_name("T9999") == "T9999"
        assert mitre.tactic_for("T1021.001") == "TA0008" and mitre.tactic_for("T9999") is None
        assert (
            mitre.tactic_order("TA0001")
            < mitre.tactic_order("TA0008")
            < mitre.tactic_order("TA0040")
        )
        assert mitre.tactic_order("TA9999") == len(mitre.TACTICS)


class TestHelpers:
    def test_dig_prefers_flat_keys_then_nests(self) -> None:
        assert dig({"a.b": 1, "a": {"b": 2}}, "a.b") == 1
        assert dig({"a": {"b": {"c": 3}}}, "a.b.c") == 3
        assert dig({"a": 1}, "a.b") is None and dig({}, "x") is None

    def test_first_and_as_list(self) -> None:
        assert (
            first({"a": "", "b": None, "c": "x"}, "a", "b", "c") == "x" and first({}, "a") is None
        )
        assert as_list(None) == [] and as_list("x") == ["x"] and as_list(("a", "b")) == ["a", "b"]

    @pytest.mark.parametrize(
        ("raw", "iso"),
        [
            ("2026-09-19T06:00:00Z", "2026-09-19T06:00:00+00:00"),
            ("2026-09-19T08:00:00+02:00", "2026-09-19T06:00:00+00:00"),
            ("2026-09-19T06:00:00", "2026-09-19T06:00:00+00:00"),
            (1789797600, "2026-09-19T06:00:00+00:00"),
            (1789797600000, "2026-09-19T06:00:00+00:00"),
            ("1789797600", "2026-09-19T06:00:00+00:00"),
        ],
    )
    def test_parse_time(self, raw: object, iso: str) -> None:
        assert parse_time(raw).isoformat() == iso and parse_time(raw).tzinfo == timezone.utc

    @pytest.mark.parametrize("raw", [None, "", "yesterday", []])
    def test_parse_time_errors(self, raw: object) -> None:
        with pytest.raises(NormalizeError):
            parse_time(raw)

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Informational", Severity.INFO),
            ("LOW", Severity.LOW),
            ("Medium", Severity.MEDIUM),
            ("high", Severity.HIGH),
            ("Critical", Severity.CRITICAL),
            ("urgent", Severity.CRITICAL),
            (5, Severity.INFO),
            (35, Severity.LOW),
            (55, Severity.MEDIUM),
            (75, Severity.HIGH),
            (95, Severity.CRITICAL),
            ("80", Severity.HIGH),
            (None, Severity.MEDIUM),
            ("weird", Severity.MEDIUM),
            (True, Severity.MEDIUM),
        ],
    )
    def test_map_severity(self, raw: object, expected: Severity) -> None:
        assert map_severity(raw) is expected


class TestSplunk:
    def test_webhook_payload(self) -> None:
        alert = splunk(
            {
                "sid": "sid1",
                "search_name": "Lateral",
                "result": {
                    "_time": "2026-09-19T06:45:00Z",
                    "event_id": "e1",
                    "rule_name": "RDP Lateral Movement",
                    "urgency": "high",
                    "src_host": "WS-042",
                    "dest": "srv-file01",
                    "user": "CORP\\Alice",
                    "src_ip": "10.20.1.42",
                    "annotations": {"mitre_attack": ["t1021.001"]},
                    "security_domain": "access",
                },
            }
        )
        assert (
            alert.id == "splunk:e1"
            and alert.severity is Severity.HIGH
            and alert.category == "access"
        )
        assert {e.key for e in alert.entities} == {
            "host:ws-042",
            "host:srv-file01",
            "user:alice",
            "ip:10.20.1.42",
        }
        assert alert.techniques == ["T1021.001"] and alert.tactics == ["TA0008"]

    def test_flat_notable_with_title_fallback_and_hash(self) -> None:
        alert = splunk(
            {
                "_time": 1789797600,
                "signature": "Bad file",
                "severity": "critical",
                "dest": "10.0.0.5",
                "file_hash": "A" * 64,
                "url": "https://evil.example/x",
                "process": "cmd.exe -password hunter2xyz",
            }
        )
        assert alert.title == "Bad file" and alert.severity is Severity.CRITICAL
        keys = {e.key for e in alert.entities}
        assert {"ip:10.0.0.5", "hash:" + "a" * 64, "domain:evil.example"} <= keys
        assert "hunter2xyz" not in alert.attributes["command_line"]

    def test_missing_title_is_rejected(self) -> None:
        with pytest.raises(NormalizeError, match="title"):
            splunk({"result": {"_time": "2026-09-19T06:00:00Z"}})


class TestSentinel:
    def _row(self, **kw: object) -> dict[str, object]:
        base: dict[str, object] = {
            "SystemAlertId": "sn1",
            "AlertName": "Sign-in from a new country",
            "AlertSeverity": "Medium",
            "Description": "d",
            "TimeGenerated": "2026-09-19T06:25:00Z",
            "Tactics": "InitialAccess, Execution",
            "Techniques": ["T1078"],
            "Entities": json.dumps(
                [
                    {"Type": "account", "Name": "alice", "UPNSuffix": "corp.example"},
                    {"Type": "ip", "Address": "198.51.100.77"},
                    {"Type": "host", "HostName": "WS-042"},
                    {"Type": "url", "Url": "https://evil.example/a"},
                    {"Type": "dns", "DomainName": "evil2.example"},
                    {"Type": "file", "FileHashes": [{"Algorithm": "SHA256", "Value": "b" * 64}]},
                ]
            ),
        }
        base.update(kw)
        return base

    def test_maps_entities_techniques_and_tactics(self) -> None:
        alert = sentinel(self._row())
        assert alert.id == "sentinel:sn1" and alert.severity is Severity.MEDIUM
        assert {e.key for e in alert.entities} == {
            "user:alice",
            "ip:198.51.100.77",
            "host:ws-042",
            "domain:evil.example",
            "domain:evil2.example",
            "hash:" + "b" * 64,
        } | {e.key for e in alert.entities if e.type.value == "url"}
        assert alert.techniques == ["T1078"] and set(alert.tactics) == {"TA0001", "TA0002"}

    def test_entities_as_list_and_techniques_as_string(self) -> None:
        alert = sentinel(
            self._row(
                Entities=[{"Type": "host", "HostName": "srv-1"}],
                Techniques="T1110, T1078",
                Tactics=["CredentialAccess"],
            )
        )
        assert [e.key for e in alert.entities] == ["host:srv-1"] and alert.techniques == [
            "T1110",
            "T1078",
        ]

    def test_bad_entities_json_is_ignored_not_fatal(self) -> None:
        assert sentinel(self._row(Entities="{not json")).entities == []


class TestCrowdstrike:
    def _detection(self, **kw: object) -> dict[str, object]:
        base: dict[str, object] = {
            "detection_id": "ldt:1",
            "max_severity_displayname": "High",
            "created_timestamp": "2026-09-19T06:04:00Z",
            "device": {
                "hostname": "WS-042",
                "local_ip": "10.20.1.42",
                "external_ip": "203.0.113.5",
            },
            "behaviors": [
                {
                    "scenario": "Suspicious PowerShell",
                    "description": "Encoded PowerShell",
                    "tactic": "Execution",
                    "tactic_id": "TA0002",
                    "technique_id": "T1059.001",
                    "cmdline": "powershell -enc AAA --password Sup3rSecret",
                    "sha256": "c" * 64,
                    "user_name": "CORP\\alice",
                    "timestamp": "2026-09-19T06:04:00Z",
                },
                {
                    "tactic": "Command and Control",
                    "technique_id": "T1071",
                    "ioc_type": "ipv4",
                    "ioc_value": "203.0.113.66",
                },
                {"ioc_type": "domain", "ioc_value": "evil.example"},
            ],
        }
        base.update(kw)
        return base

    def test_maps_device_and_behaviors(self) -> None:
        alert = crowdstrike(self._detection())
        assert (
            alert.id == "crowdstrike:ldt:1"
            and alert.title == "Suspicious PowerShell"
            and alert.category == "edr"
        )
        assert {e.key for e in alert.entities} == {
            "host:ws-042",
            "ip:10.20.1.42",
            "ip:203.0.113.5",
            "user:alice",
            "hash:" + "c" * 64,
            "ip:203.0.113.66",
            "domain:evil.example",
        }
        assert set(alert.techniques) == {"T1059.001", "T1071"} and {"TA0002", "TA0011"} <= set(
            alert.tactics
        )
        assert "Sup3rSecret" not in alert.attributes["command_line"]

    def test_numeric_severity_and_no_behaviors(self) -> None:
        alert = crowdstrike(
            {
                "detection_id": "x",
                "max_severity": 95,
                "created_timestamp": "2026-09-19T06:00:00Z",
                "device": {"hostname": "h1"},
            }
        )
        assert alert.severity is Severity.CRITICAL and alert.title == "CrowdStrike detection"


class TestElastic:
    def test_flat_dotted_documents(self) -> None:
        alert = elastic(
            {
                "kibana.alert.uuid": "u1",
                "kibana.alert.rule.name": "Malicious Attachment",
                "kibana.alert.severity": "high",
                "@timestamp": "2026-09-19T06:00:00Z",
                "host.name": "WS-042",
                "user.name": "alice",
                "source.ip": "10.1.1.1",
                "destination.ip": "203.0.113.66",
                "file.hash.sha256": "d" * 64,
                "dns.question.name": "evil.example",
                "url.full": "https://evil.example/x",
                "email.from.address": "bad@evil.example",
                "process.command_line": "winword.exe /password=Xyzzy123",
                "kibana.alert.rule.threat": [
                    {
                        "tactic": {"id": "TA0001"},
                        "technique": [{"id": "T1566", "subtechnique": [{"id": "T1566.001"}]}],
                    }
                ],
            }
        )
        assert alert.id == "elastic:u1" and alert.severity is Severity.HIGH
        assert {
            "host:ws-042",
            "user:alice",
            "ip:10.1.1.1",
            "ip:203.0.113.66",
            "domain:evil.example",
            "email:bad@evil.example",
        } <= {e.key for e in alert.entities}
        assert alert.techniques == ["T1566", "T1566.001"] and alert.tactics == ["TA0001"]
        assert "Xyzzy123" not in alert.attributes["command_line"]

    def test_nested_documents_and_risk_score_severity(self) -> None:
        alert = elastic(
            {
                "@timestamp": "2026-09-19T06:00:00Z",
                "kibana": {
                    "alert": {
                        "rule": {
                            "name": "Rule",
                            "threat": [{"tactic": {"name": "Execution"}, "technique": []}],
                        },
                        "risk_score": 99,
                    }
                },
                "host": {"name": "h1"},
            }
        )
        assert (
            alert.title == "Rule"
            and alert.severity is Severity.CRITICAL
            and alert.tactics == ["TA0002"]
        )
        assert alert.id.startswith("elastic:") and len(alert.id) == len("elastic:") + 16


class TestGenericAndRegistry:
    def test_valid_record_and_redaction(self) -> None:
        alert = generic(
            {
                "id": "g1",
                "timestamp": "2026-09-19T06:00:00Z",
                "title": "T",
                "severity": "high",
                "description": "password=Sup3rSecret",
                "entities": [{"type": "host", "value": "h1"}],
                "attributes": {"cmd": "x --token abc12345"},
            }
        )
        assert (
            alert.source == "generic"
            and "Sup3rSecret" not in alert.description
            and "abc12345" not in alert.attributes["cmd"]
        )

    def test_strict_validation(self) -> None:
        with pytest.raises(NormalizeError):
            generic(
                {"id": "g", "timestamp": "2026-09-19T06:00:00Z", "title": "T", "severity": "loud"}
            )
        with pytest.raises(NormalizeError):
            generic(
                {
                    "id": "g",
                    "timestamp": "2026-09-19T06:00:00Z",
                    "title": "T",
                    "severity": "low",
                    "surprise": 1,
                }
            )

    def test_stable_namespaced_ids_and_cross_vendor_user_identity(self) -> None:
        a = splunk(
            {
                "result": {
                    "_time": "2026-09-19T06:00:00Z",
                    "rule_name": "X",
                    "user": "CORP\\alice",
                    "dest": "h1",
                }
            }
        )
        b = splunk(
            {
                "result": {
                    "_time": "2026-09-19T06:00:00Z",
                    "rule_name": "X",
                    "user": "CORP\\alice",
                    "dest": "h1",
                }
            }
        )
        assert a.id == b.id and a.id.startswith("splunk:")
        s = sentinel(
            {
                "AlertName": "Y",
                "TimeGenerated": "2026-09-19T06:00:00Z",
                "Entities": [{"Type": "account", "Name": "alice", "UPNSuffix": "corp.example"}],
            }
        )
        assert {e.key for e in a.entities} & {e.key for e in s.entities} == {"user:alice"}

    def test_registry_covers_every_source(self) -> None:
        assert set(NORMALIZERS) == {"splunk", "sentinel", "crowdstrike", "elastic", "generic"}
