"""Shared fixtures and builders."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Iterator, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from socagent import mitre
from socagent.config import Context, Settings
from socagent.container import build_service
from socagent.db import Database
from socagent.models import Alert, Entity, EntityType, Severity
from socagent.providers.http import JsonClient
from socagent.service import IRService

START = datetime(2026, 9, 19, 6, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 9, 19, 14, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIGS = REPO_ROOT / "configs"


@pytest.fixture(autouse=True)
def _close_databases(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close every SQLite connection a test opens, so none leak."""
    opened: list[Database] = []
    original = Database.__init__

    def tracking(self: Database, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(Database, "__init__", tracking)
    yield
    for db in opened:
        with contextlib.suppress(Exception):
            db.close()


def make_alert(
    alert_id: str,
    minutes: float = 0,
    *,
    title: str = "Suspicious activity",
    severity: str = "medium",
    hosts: Sequence[str] = (),
    users: Sequence[str] = (),
    ips: Sequence[str] = (),
    hashes: Sequence[str] = (),
    domains: Sequence[str] = (),
    techniques: Sequence[str] = (),
    tactics: Sequence[str] | None = None,
    source: str = "generic",
    description: str = "",
    attributes: dict[str, str] | None = None,
) -> Alert:
    """A normalised alert at ``START + minutes``."""
    entities = (
        [Entity(type=EntityType.HOST, value=h) for h in hosts]
        + [Entity(type=EntityType.USER, value=u) for u in users]
        + [Entity(type=EntityType.IP, value=i) for i in ips]
        + [Entity(type=EntityType.HASH, value=h) for h in hashes]
        + [Entity(type=EntityType.DOMAIN, value=d) for d in domains]
    )
    if tactics is None:
        tactics = list(dict.fromkeys(t for tech in techniques if (t := mitre.tactic_for(tech))))
    return Alert(
        id=alert_id,
        source=source,  # type: ignore[arg-type]
        timestamp=START + timedelta(minutes=minutes),
        title=title,
        severity=Severity(severity),
        description=description,
        entities=entities,
        techniques=list(techniques),
        tactics=list(tactics),
        attributes=attributes or {},
    )


def write_configs(
    tmp_path: Path,
    *,
    assets: list[dict[str, Any]] | None = None,
    identities: list[dict[str, Any]] | None = None,
    indicators: list[dict[str, Any]] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, object]:
    """Write context files under ``tmp_path`` and return the matching Settings overrides."""
    overrides: dict[str, object] = {}
    if assets is not None or identities is not None:
        path = tmp_path / "assets.yaml"
        path.write_text(
            yaml.safe_dump({"assets": assets or [], "identities": identities or []}),
            encoding="utf-8",
        )
        overrides["assets_file"] = path
    if indicators is not None:
        path = tmp_path / "iocs.json"
        path.write_text(json.dumps({"indicators": indicators}), encoding="utf-8")
        overrides["iocs_file"] = path
    if policy is not None:
        path = tmp_path / "policy.yaml"
        path.write_text(yaml.safe_dump(policy), encoding="utf-8")
        overrides["policy_file"] = path
    return overrides


def make_settings(tmp_path: Path, **overrides: object) -> Settings:
    """Settings that ignore the developer's environment and write only under ``tmp_path``."""
    base: dict[str, object] = {
        "db_path": tmp_path / "soc.db",
        "retry_min_wait": 0.0,
        "retry_max_wait": 0.0,
        "log_level": "CRITICAL",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def make_service(
    tmp_path: Path, *, clock: Callable[[], datetime] | None = None, **overrides: object
) -> IRService:
    """A service with the demo context (assets, indicators, policy) unless overridden."""
    defaults: dict[str, object] = {
        "assets_file": CONFIGS / "assets.example.yaml",
        "iocs_file": CONFIGS / "iocs.example.json",
        "policy_file": CONFIGS / "policy.example.yaml",
    }
    defaults.update(overrides)
    return build_service(make_settings(tmp_path, **defaults), clock=clock or (lambda: NOW))


def json_client(
    handler: Callable[[httpx.Request], httpx.Response], attempts: int = 2
) -> JsonClient:
    """A JsonClient backed by an in-process mock transport."""
    return JsonClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        attempts=attempts,
        min_wait=0.0,
        max_wait=0.0,
    )


def empty_context() -> Context:
    return Context()
