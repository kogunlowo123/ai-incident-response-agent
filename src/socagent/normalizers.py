"""Vendor alert normalisers.

Each function turns one vendor record (a decoded JSON object) into a normalised :class:`Alert`.
Field names follow each product's commonly documented alert and detection schemas. Exports vary by
version and configuration, so lookups are tolerant (dotted or nested keys, several aliases) and a
record that cannot be mapped is rejected with a reason instead of being guessed at. Verify the
mapping against a real export from your environment before relying on it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any

from socagent import mitre
from socagent.models import Alert, Entity, EntityType, Severity
from socagent.security import (
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_host,
    normalize_ip,
    normalize_user,
    redact,
    url_domain,
)

Normalizer = Callable[[dict[str, Any]], Alert]


class NormalizeError(ValueError):
    """Raised when a record cannot be mapped to an alert."""


# -- helpers ---------------------------------------------------------------------------------------


def dig(record: dict[str, Any], path: str) -> Any:
    """Read ``path`` from ``record``, trying the flat dotted key first, then nested objects."""
    if path in record:
        return record[path]
    current: Any = record
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def first(record: dict[str, Any], *paths: str) -> Any:
    """The first non-empty value among ``paths``."""
    for path in paths:
        value = dig(record, path)
        if value not in (None, "", [], {}):
            return value
    return None


def as_list(value: Any) -> list[Any]:
    """Wrap a scalar in a list; pass lists through; treat ``None`` as empty."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def parse_time(value: Any) -> datetime:
    """Parse ISO 8601 strings and epoch seconds or milliseconds into UTC."""
    if isinstance(value, datetime):
        return (
            value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        )
    if isinstance(value, (int, float)) or (
        isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value.strip())
    ):
        number = float(value)
        if number > 1e11:
            number /= 1000.0
        return datetime.fromtimestamp(number, tz=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise NormalizeError(f"unrecognised timestamp {value!r}") from exc
        return (
            moment.astimezone(timezone.utc)
            if moment.tzinfo
            else moment.replace(tzinfo=timezone.utc)
        )
    raise NormalizeError("missing timestamp")


def map_severity(value: Any) -> Severity:
    """Map vendor severities (words, or numbers 0 to 100) to :class:`Severity`."""
    if isinstance(value, bool) or value is None:
        return Severity.MEDIUM
    if isinstance(value, (int, float)) or (
        isinstance(value, str) and re.fullmatch(r"\d+(\.\d+)?", value.strip())
    ):
        score = float(value)
        for limit, severity in (
            (20, Severity.INFO),
            (40, Severity.LOW),
            (70, Severity.MEDIUM),
            (90, Severity.HIGH),
        ):
            if score < limit:
                return severity
        return Severity.CRITICAL
    text = str(value).strip().lower()
    table = {
        "informational": Severity.INFO,
        "info": Severity.INFO,
        "none": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "high": Severity.HIGH,
        "severe": Severity.HIGH,
        "critical": Severity.CRITICAL,
        "urgent": Severity.CRITICAL,
    }
    return table.get(text, Severity.MEDIUM)


def _clean_url(value: str) -> str:
    return value.strip()[:500]


class EntityBag:
    """Collects normalised entities, silently dropping values that fail validation."""

    def __init__(self) -> None:
        self._seen: dict[str, Entity] = {}

    def add(self, kind: EntityType, raw: Any) -> None:
        for item in as_list(raw):
            if not isinstance(item, str) or not item.strip():
                continue
            value = {
                EntityType.HOST: normalize_host,
                EntityType.USER: normalize_user,
                EntityType.IP: normalize_ip,
                EntityType.DOMAIN: normalize_domain,
                EntityType.HASH: normalize_hash,
                EntityType.EMAIL: normalize_email,
                EntityType.URL: _clean_url,
            }[kind](item)
            if value:
                entity = Entity(type=kind, value=value)
                self._seen[entity.key] = entity
            if kind is EntityType.URL and (domain := url_domain(item)):
                self._seen[f"domain:{domain}"] = Entity(type=EntityType.DOMAIN, value=domain)

    def entities(self) -> list[Entity]:
        return list(self._seen.values())


def mitre_fields(techniques: Iterable[Any], tactics: Iterable[Any]) -> tuple[list[str], list[str]]:
    """Normalise technique and tactic values, adding the tactics implied by known techniques."""
    tech = [
        t for raw in techniques if isinstance(raw, str) and (t := mitre.normalize_technique(raw))
    ]
    tact = [t for raw in tactics if isinstance(raw, str) and (t := mitre.normalize_tactic(raw))]
    for technique in tech:
        implied = mitre.tactic_for(technique)
        if implied and implied not in tact:
            tact.append(implied)
    return list(dict.fromkeys(tech)), list(dict.fromkeys(tact))


def alert_id(
    source: str, vendor_id: Any, title: str, when: datetime, entity_keys: list[str]
) -> str:
    """The vendor id when present, otherwise a stable hash of the alert's identifying content."""
    if vendor_id not in (None, ""):
        return f"{source}:{str(vendor_id)[:150]}"
    digest = hashlib.sha256(
        "|".join([source, title, when.isoformat(), *sorted(entity_keys)]).encode()
    ).hexdigest()[:16]
    return f"{source}:{digest}"


def build(
    source: str,
    record: dict[str, Any],
    *,
    vendor_id: Any,
    title: Any,
    when: Any,
    severity: Any,
    description: Any,
    category: Any,
    bag: EntityBag,
    techniques: Iterable[Any],
    tactics: Iterable[Any],
    attributes: dict[str, Any],
) -> Alert:
    """Assemble and validate an :class:`Alert` from mapped fields."""
    if not isinstance(title, str) or not title.strip():
        raise NormalizeError("missing alert title")
    moment = parse_time(when)
    tech, tact = mitre_fields(techniques, tactics)
    attrs = {k: redact(str(v))[:1000] for k, v in attributes.items() if v not in (None, "", [], {})}
    entities = bag.entities()
    return Alert(
        id=alert_id(source, vendor_id, title, moment, [e.key for e in entities]),
        source=source,
        timestamp=moment,
        title=title.strip()[:300],
        severity=map_severity(severity),
        description=redact(str(description or ""))[:2000],
        category=str(category or "")[:100],
        entities=entities,
        techniques=tech,
        tactics=tact,
        attributes=dict(list(attrs.items())[:30]),
    )


# -- vendors -----------------------------------------------------------------------------------------


def splunk(record: dict[str, Any]) -> Alert:
    """Splunk alert-action webhook payloads (``{"result": {...}, "search_name": ...}``) and flat notables."""
    result = record.get("result") if isinstance(record.get("result"), dict) else record
    assert isinstance(result, dict)
    bag = EntityBag()
    for key in ("src", "src_ip", "dest_ip", "dest", "src_host", "dest_host", "host"):
        value = result.get(key)
        if isinstance(value, str) and normalize_ip(value):
            bag.add(EntityType.IP, value)
        elif key in {"dest", "dest_host", "src_host", "host"}:
            bag.add(EntityType.HOST, value)
    bag.add(EntityType.USER, [result.get("user"), result.get("src_user"), result.get("dest_user")])
    bag.add(
        EntityType.HASH,
        [result.get("file_hash"), result.get("hash"), result.get("sha256"), result.get("md5")],
    )
    bag.add(EntityType.URL, result.get("url"))
    bag.add(EntityType.DOMAIN, [result.get("domain"), result.get("query")])
    return build(
        "splunk",
        record,
        vendor_id=first(result, "event_id", "_cd") or first(record, "sid"),
        title=first(result, "rule_name", "signature") or first(record, "search_name"),
        when=first(result, "_time", "time", "timestamp"),
        severity=first(result, "urgency", "severity"),
        description=first(result, "description", "_raw"),
        category=first(result, "security_domain", "category"),
        bag=bag,
        techniques=as_list(
            first(result, "annotations.mitre_attack", "mitre_attack", "mitre_technique_id")
        ),
        tactics=as_list(first(result, "annotations.mitre_attack_tactic", "mitre_tactic")),
        attributes={
            "command_line": first(result, "process", "cmdline", "command"),
            "signature": result.get("signature"),
        },
    )


def _sentinel_entities(bag: EntityBag, raw: Any) -> None:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return
    for entity in as_list(raw):
        if not isinstance(entity, dict):
            continue
        kind = str(entity.get("Type", "")).lower()
        if kind == "host":
            bag.add(EntityType.HOST, entity.get("HostName") or entity.get("Name"))
        elif kind == "account":
            bag.add(EntityType.USER, entity.get("Name") or entity.get("AccountName"))
        elif kind == "ip":
            bag.add(EntityType.IP, entity.get("Address"))
        elif kind == "url":
            bag.add(EntityType.URL, entity.get("Url"))
        elif kind == "dns":
            bag.add(EntityType.DOMAIN, entity.get("DomainName"))
        elif kind == "file":
            for h in as_list(entity.get("FileHashes")):
                if isinstance(h, dict):
                    bag.add(EntityType.HASH, h.get("Value"))


def sentinel(record: dict[str, Any]) -> Alert:
    """Microsoft Sentinel ``SecurityAlert`` rows."""
    bag = EntityBag()
    _sentinel_entities(bag, record.get("Entities"))
    bag.add(
        EntityType.HOST,
        record.get("CompromisedEntity")
        if "." in str(record.get("CompromisedEntity", ""))
        or "-" in str(record.get("CompromisedEntity", ""))
        else None,
    )
    techniques = record.get("Techniques") or []
    if isinstance(techniques, str):
        try:
            techniques = json.loads(techniques)
        except ValueError:
            techniques = [t for t in re.split(r"[,\s]+", techniques) if t]
    tactics = record.get("Tactics") or []
    if isinstance(tactics, str):
        tactics = [t for t in re.split(r"[,]+", tactics) if t]
    return build(
        "sentinel",
        record,
        vendor_id=record.get("SystemAlertId"),
        title=record.get("AlertName"),
        when=first(record, "TimeGenerated", "StartTime"),
        severity=record.get("AlertSeverity"),
        description=record.get("Description"),
        category=record.get("ProviderName") or record.get("VendorName"),
        bag=bag,
        techniques=as_list(techniques),
        tactics=as_list(tactics),
        attributes={"product": record.get("ProductName")},
    )


def crowdstrike(record: dict[str, Any]) -> Alert:
    """CrowdStrike Falcon detection summaries (device plus behaviors)."""
    device: dict[str, Any] = record["device"] if isinstance(record.get("device"), dict) else {}
    behaviors = [b for b in as_list(record.get("behaviors")) if isinstance(b, dict)]
    bag = EntityBag()
    bag.add(EntityType.HOST, [device.get("hostname"), record.get("hostname")])
    bag.add(EntityType.IP, [device.get("local_ip"), device.get("external_ip")])
    techniques: list[Any] = []
    tactics: list[Any] = []
    commands: list[str] = []
    ioc_types = {
        "ipv4": EntityType.IP,
        "ipv6": EntityType.IP,
        "domain": EntityType.DOMAIN,
        "sha256": EntityType.HASH,
        "md5": EntityType.HASH,
    }
    for b in behaviors:
        bag.add(EntityType.USER, b.get("user_name"))
        bag.add(EntityType.HASH, [b.get("sha256"), b.get("md5")])
        ioc_kind = ioc_types.get(str(b.get("ioc_type", "")).lower())
        if ioc_kind:
            bag.add(ioc_kind, b.get("ioc_value"))
        techniques.append(b.get("technique_id"))
        tactics.append(b.get("tactic_id") or b.get("tactic"))
        if b.get("cmdline"):
            commands.append(str(b["cmdline"]))
    severity = first(record, "max_severity_displayname", "max_severity")
    title = (
        first(record, "title")
        or (behaviors[0].get("scenario") or behaviors[0].get("description") if behaviors else None)
        or "CrowdStrike detection"
    )
    return build(
        "crowdstrike",
        record,
        vendor_id=record.get("detection_id"),
        title=title,
        when=first(record, "created_timestamp", "first_behavior", "timestamp")
        or (behaviors[0].get("timestamp") if behaviors else None),
        severity=severity,
        description=behaviors[0].get("description") if behaviors else record.get("description"),
        category="edr",
        bag=bag,
        techniques=techniques,
        tactics=tactics,
        attributes={"command_line": " ; ".join(commands)},
    )


def elastic(record: dict[str, Any]) -> Alert:
    """Elastic Security detection alerts (``kibana.alert.*`` plus ECS fields)."""
    bag = EntityBag()
    bag.add(EntityType.HOST, first(record, "host.name", "host.hostname"))
    bag.add(EntityType.USER, first(record, "user.name"))
    bag.add(EntityType.IP, [first(record, "source.ip"), first(record, "destination.ip")])
    bag.add(
        EntityType.HASH,
        [
            first(record, "process.hash.sha256"),
            first(record, "file.hash.sha256"),
            first(record, "file.hash.md5"),
        ],
    )
    bag.add(EntityType.DOMAIN, first(record, "dns.question.name"))
    bag.add(EntityType.URL, first(record, "url.full"))
    bag.add(EntityType.EMAIL, first(record, "email.from.address"))
    techniques: list[Any] = []
    tactics: list[Any] = []
    for threat in as_list(first(record, "kibana.alert.rule.threat", "threat")):
        if not isinstance(threat, dict):
            continue
        tactic = threat.get("tactic")
        if isinstance(tactic, dict):
            tactics.append(tactic.get("id") or tactic.get("name"))
        for tech in as_list(threat.get("technique")):
            if isinstance(tech, dict):
                techniques.append(tech.get("id"))
                techniques.extend(
                    sub.get("id")
                    for sub in as_list(tech.get("subtechnique"))
                    if isinstance(sub, dict)
                )
    return build(
        "elastic",
        record,
        vendor_id=first(record, "kibana.alert.uuid", "_id"),
        title=first(record, "kibana.alert.rule.name", "rule.name"),
        when=first(record, "@timestamp", "kibana.alert.original_time"),
        severity=first(record, "kibana.alert.severity", "kibana.alert.risk_score"),
        description=first(record, "kibana.alert.rule.description", "message"),
        category=first(record, "event.category"),
        bag=bag,
        techniques=techniques,
        tactics=tactics,
        attributes={
            "command_line": first(record, "process.command_line"),
            "process": first(record, "process.name"),
        },
    )


def generic(record: dict[str, Any]) -> Alert:
    """Records already in the normalised schema. Validated strictly; secrets are redacted."""
    data = dict(record)
    data["source"] = "generic"
    data["description"] = redact(str(data.get("description", "")))
    data["attributes"] = {k: redact(str(v)) for k, v in (data.get("attributes") or {}).items()}
    try:
        return Alert.model_validate(data)
    except ValueError as exc:
        raise NormalizeError(str(exc).splitlines()[0]) from exc


NORMALIZERS: dict[str, Normalizer] = {
    "splunk": splunk,
    "sentinel": sentinel,
    "crowdstrike": crowdstrike,
    "elastic": elastic,
    "generic": generic,
}
