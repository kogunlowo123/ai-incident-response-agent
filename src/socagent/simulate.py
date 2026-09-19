"""Deterministic synthetic alerts in each vendor's format, for demos and tests.

The scenario contains a multi-stage intrusion (phishing, PowerShell execution, command and control,
a suspicious sign-in, RDP lateral movement to a file server, exfiltration), a separate password
attack that ends in a successful logon, and a large volume of unrelated low-severity noise including a
scanner address that touches many hosts. Addresses come from the documentation ranges reserved by
RFC 5737 and RFC 2544.
"""

from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

MALWARE_SHA256 = hashlib.sha256(b"demo-malware-sample").hexdigest()
C2_IP = "203.0.113.66"
ATTACKER_IP = "198.51.100.23"
SCANNER_IP = "198.18.0.1"

Records = dict[str, list[dict[str, Any]]]


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def simulate(*, start: datetime, seed: int = 7, noise: int = 40) -> Records:
    """Return records keyed by source (``splunk``, ``sentinel``, ``crowdstrike``, ``elastic``)."""
    rng = random.Random(seed)  # noqa: S311  (reproducible synthetic data, not security)

    def at(minutes: int) -> datetime:
        return start + timedelta(minutes=minutes)

    out: Records = {"splunk": [], "sentinel": [], "crowdstrike": [], "elastic": []}

    out["elastic"].append(
        {
            "kibana.alert.uuid": "el-0001",
            "kibana.alert.rule.name": "Malicious Email Attachment Opened",
            "kibana.alert.severity": "high",
            "kibana.alert.rule.description": "A user opened an Office attachment that spawned a script host.",
            "@timestamp": _iso(at(0)),
            "host.name": "WS-042",
            "user.name": "alice",
            "email.from.address": "billing@evil-cdn.example",
            "file.hash.sha256": MALWARE_SHA256,
            "kibana.alert.rule.threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {"id": "TA0001", "name": "Initial Access"},
                    "technique": [
                        {
                            "id": "T1566",
                            "name": "Phishing",
                            "subtechnique": [
                                {"id": "T1566.001", "name": "Spearphishing Attachment"}
                            ],
                        }
                    ],
                }
            ],
        }
    )
    out["crowdstrike"].append(
        {
            "detection_id": "ldt:cs-0001",
            "max_severity_displayname": "High",
            "created_timestamp": _iso(at(4)),
            "device": {"hostname": "WS-042", "local_ip": "10.20.1.42"},
            "behaviors": [
                {
                    "scenario": "Suspicious PowerShell",
                    "description": "Encoded PowerShell launched by an Office process",
                    "tactic": "Execution",
                    "tactic_id": "TA0002",
                    "technique_id": "T1059.001",
                    "cmdline": "powershell.exe -enc SQBFAFgA -password hunter2xyz",
                    "sha256": MALWARE_SHA256,
                    "user_name": "CORP\\alice",
                    "timestamp": _iso(at(4)),
                }
            ],
        }
    )
    out["crowdstrike"].append(
        {
            "detection_id": "ldt:cs-0002",
            "max_severity_displayname": "Critical",
            "created_timestamp": _iso(at(9)),
            "device": {"hostname": "WS-042", "local_ip": "10.20.1.42"},
            "behaviors": [
                {
                    "scenario": "Command and control beaconing",
                    "description": "Periodic outbound connections to a known-bad address",
                    "tactic": "Command and Control",
                    "tactic_id": "TA0011",
                    "technique_id": "T1071",
                    "ioc_type": "ipv4",
                    "ioc_value": C2_IP,
                    "user_name": "CORP\\alice",
                    "timestamp": _iso(at(9)),
                }
            ],
        }
    )
    out["sentinel"].append(
        {
            "SystemAlertId": "sn-0001",
            "AlertName": "Sign-in from a new country",
            "AlertSeverity": "Medium",
            "Description": "A sign-in for this account came from an unfamiliar country.",
            "TimeGenerated": _iso(at(25)),
            "Tactics": "InitialAccess",
            "Techniques": ["T1078"],
            "Entities": json.dumps(
                [
                    {"Type": "account", "Name": "alice", "UPNSuffix": "corp.example"},
                    {"Type": "ip", "Address": "198.51.100.77"},
                ]
            ),
        }
    )
    out["splunk"].append(
        {
            "sid": "scheduler_1",
            "search_name": "Remote Desktop Logon from Workstation to Server",
            "result": {
                "_time": _iso(at(45)),
                "event_id": "sp-0001",
                "rule_name": "Lateral Movement via RDP",
                "urgency": "high",
                "src_host": "ws-042",
                "dest": "srv-file01",
                "user": "CORP\\alice",
                "annotations": {"mitre_attack": ["T1021.001"]},
                "security_domain": "access",
            },
        }
    )
    out["sentinel"].append(
        {
            "SystemAlertId": "sn-0002",
            "AlertName": "Large outbound data transfer",
            "AlertSeverity": "High",
            "Description": "Unusually large upload to an external address.",
            "TimeGenerated": _iso(at(70)),
            "Tactics": ["Exfiltration"],
            "Techniques": ["T1041"],
            "Entities": json.dumps(
                [{"Type": "host", "HostName": "srv-file01"}, {"Type": "ip", "Address": C2_IP}]
            ),
        }
    )

    out["splunk"].append(
        {
            "result": {
                "_time": _iso(at(120)),
                "event_id": "sp-0002",
                "rule_name": "Multiple Failed Logons",
                "urgency": "medium",
                "src_ip": ATTACKER_IP,
                "user": "bob",
                "annotations": {"mitre_attack": ["T1110.003"]},
            },
            "search_name": "Password spray",
        }
    )
    out["splunk"].append(
        {
            "result": {
                "_time": _iso(at(133)),
                "event_id": "sp-0003",
                "rule_name": "Successful Logon After Multiple Failures",
                "urgency": "high",
                "src_ip": ATTACKER_IP,
                "user": "bob",
                "annotations": {"mitre_attack": ["T1078"]},
            },
            "search_name": "Logon after failures",
        }
    )

    for index in range(noise):
        when = at(rng.randint(0, 360))
        record = {
            "result": {
                "_time": _iso(when),
                "event_id": f"sp-noise-{index}",
                "rule_name": rng.choice(
                    ["Port scan detected", "Outdated software", "Unusual DNS query"]
                ),
                "urgency": rng.choice(["low", "informational"]),
                "src_ip": SCANNER_IP if index % 4 else "192.0.2.10",
                "dest": f"host-{index:03d}",
                "user": f"user{index:03d}",
            },
            "search_name": "noise",
        }
        out["splunk"].append(record)
    return out


def write_records(records: Records, directory: Path) -> list[Path]:
    """Write each source's records as ``<source>.jsonl`` in ``directory``."""
    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for source, items in records.items():
        path = directory / f"{source}.jsonl"
        path.write_text("".join(json.dumps(item) + "\n" for item in items), encoding="utf-8")
        paths.append(path)
    return paths
