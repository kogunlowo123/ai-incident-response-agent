"""A small MITRE ATT&CK reference: tactics in kill-chain order and the techniques the rules use.

This is a curated subset, not the full matrix. Unknown but well-formed technique ids are accepted and
kept; they simply have no name or tactic mapping here. Verify identifiers against the current ATT&CK
release before citing them in a report.
"""

from __future__ import annotations

import re

TACTICS: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}
"""Tactics ordered roughly along the attack lifecycle."""

_TACTIC_BY_NAME = {name.lower().replace(" ", "-"): tid for tid, name in TACTICS.items()}
_TACTIC_BY_NAME.update({name.lower(): tid for tid, name in TACTICS.items()})

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1059": ("Command and Scripting Interpreter", "TA0002"),
    "T1059.001": ("PowerShell", "TA0002"),
    "T1053": ("Scheduled Task/Job", "TA0003"),
    "T1547": ("Boot or Logon Autostart Execution", "TA0003"),
    "T1078": ("Valid Accounts", "TA0001"),
    "T1190": ("Exploit Public-Facing Application", "TA0001"),
    "T1566": ("Phishing", "TA0001"),
    "T1566.001": ("Spearphishing Attachment", "TA0001"),
    "T1562": ("Impair Defenses", "TA0005"),
    "T1003": ("OS Credential Dumping", "TA0006"),
    "T1003.001": ("LSASS Memory", "TA0006"),
    "T1110": ("Brute Force", "TA0006"),
    "T1110.003": ("Password Spraying", "TA0006"),
    "T1021": ("Remote Services", "TA0008"),
    "T1021.001": ("Remote Desktop Protocol", "TA0008"),
    "T1071": ("Application Layer Protocol", "TA0011"),
    "T1105": ("Ingress Tool Transfer", "TA0011"),
    "T1041": ("Exfiltration Over C2 Channel", "TA0010"),
    "T1048": ("Exfiltration Over Alternative Protocol", "TA0010"),
    "T1486": ("Data Encrypted for Impact", "TA0040"),
    "T1490": ("Inhibit System Recovery", "TA0040"),
}

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def normalize_technique(value: str) -> str | None:
    """Uppercase a technique id such as ``t1059.001``; ``None`` if malformed."""
    candidate = value.strip().upper()
    return candidate if _TECHNIQUE_ID.match(candidate) else None


def normalize_tactic(value: str) -> str | None:
    """Map a tactic id (``TA0002``) or name (``Execution``, ``lateral-movement``) to its id."""
    candidate = value.strip()
    if candidate.upper() in TACTICS:
        return candidate.upper()
    return _TACTIC_BY_NAME.get(candidate.lower())


def technique_name(technique: str) -> str:
    """Human name for ``technique`` (its parent's name if a sub-technique is unknown)."""
    known = TECHNIQUES.get(technique) or TECHNIQUES.get(technique.split(".")[0])
    return known[0] if known else technique


def tactic_for(technique: str) -> str | None:
    """The tactic id associated with ``technique`` in this catalog."""
    known = TECHNIQUES.get(technique) or TECHNIQUES.get(technique.split(".")[0])
    return known[1] if known else None


def tactic_order(tactic: str) -> int:
    """Position of ``tactic`` in the attack lifecycle (unknown tactics sort last)."""
    ids = list(TACTICS)
    return ids.index(tactic) if tactic in ids else len(ids)
