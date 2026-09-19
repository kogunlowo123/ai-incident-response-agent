"""Configuration: environment settings, response policy and context files (assets, identities, IOCs)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from socagent.errors import ConfigurationError
from socagent.models import Criticality
from socagent.security import (
    normalize_domain,
    normalize_hash,
    normalize_host,
    normalize_ip,
    normalize_user,
)


class Asset(BaseModel):
    """An inventory entry."""

    model_config = ConfigDict(extra="forbid")

    name: str
    criticality: Criticality = Criticality.MEDIUM
    owner: str = ""
    service: str = ""
    tags: list[str] = Field(default_factory=list)


class Identity(BaseModel):
    """A user or service account."""

    model_config = ConfigDict(extra="forbid")

    name: str
    privileged: bool = False
    service_account: bool = False
    owner: str = ""


class Indicator(BaseModel):
    """A known-bad indicator from a threat intelligence feed."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["ip", "domain", "hash"]
    value: str
    kind: str = "malicious"
    confidence: int = Field(default=70, ge=0, le=100)
    source: str = "feed"


class Policy(BaseModel):
    """Response policy: what may never be touched and who may approve what."""

    model_config = ConfigDict(extra="forbid")

    protected_hosts: list[str] = Field(default_factory=list)
    protected_users: list[str] = Field(default_factory=list)
    protected_ips: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=list)
    senior_approvers: list[str] = Field(default_factory=list)
    noise_users: list[str] = Field(
        default_factory=lambda: [
            "system",
            "-",
            "anonymous logon",
            "local service",
            "network service",
        ]
    )
    noise_ips: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1", "0.0.0.0"])  # noqa: S104
    max_entity_degree: int = Field(default=25, ge=2)
    correlation_window_minutes: int = Field(default=240, ge=1)
    approval_ttl_minutes: int = Field(default=60, ge=1)
    singleton_min_severity: Literal["info", "low", "medium", "high", "critical"] = "medium"

    @model_validator(mode="after")
    def _normalise(self) -> Policy:
        self.protected_hosts = [h for v in self.protected_hosts if (h := normalize_host(v))]
        self.protected_users = [u for v in self.protected_users if (u := normalize_user(v))]
        self.protected_ips = [i for v in self.protected_ips if (i := normalize_ip(v))]
        self.noise_users = [u for v in self.noise_users if (u := normalize_user(v))]
        self.noise_ips = [i for v in self.noise_ips if (i := normalize_ip(v))]
        return self


class Context(BaseModel):
    """Asset, identity and indicator context used during investigation."""

    assets: dict[str, Asset] = Field(default_factory=dict)
    identities: dict[str, Identity] = Field(default_factory=dict)
    indicators: dict[str, Indicator] = Field(default_factory=dict)


class Settings(BaseSettings):
    """Runtime settings from ``SOCAGENT_*`` environment variables and ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="SOCAGENT_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    db_path: Path = Path(".socagent/socagent.db")
    assets_file: Path | None = None
    iocs_file: Path | None = None
    policy_file: Path | None = None
    execution_mode: Literal["dry_run", "live"] = "dry_run"
    connector_url: SecretStr | None = None
    max_line_bytes: int = Field(default=200_000, ge=1000)
    max_lines: int = Field(default=1_000_000, ge=1)

    llm_provider: Literal["none", "openai", "anthropic"] = "none"
    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("SOCAGENT_OPENAI_API_KEY", "OPENAI_API_KEY")
    )
    openai_base_url: str = "https://api.openai.com/v1"
    openai_chat_model: str = "gpt-4o-mini"
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("SOCAGENT_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_model: str = "claude-sonnet-5"
    anthropic_max_tokens: int = Field(default=500, gt=0)

    http_timeout_seconds: float = Field(default=30.0, gt=0)
    retry_attempts: int = Field(default=3, ge=1)
    retry_min_wait: float = Field(default=0.5, ge=0)
    retry_max_wait: float = Field(default=8.0, ge=0)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "WARNING"
    log_json: bool = True

    @model_validator(mode="after")
    def _check_consistency(self) -> Settings:
        if self.retry_max_wait < self.retry_min_wait:
            raise ValueError("retry_max_wait must be >= retry_min_wait")
        if self.execution_mode == "live" and self.connector_url is None:
            raise ValueError("execution_mode=live requires SOCAGENT_CONNECTOR_URL")
        return self


def _read_yaml(path: Path) -> dict[str, object]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"{path} must contain a mapping at the top level")
    return data


def load_policy(path: Path | None) -> Policy:
    """Load the response policy from YAML, or the defaults when ``path`` is ``None``."""
    if path is None:
        return Policy()
    try:
        return Policy.model_validate(_read_yaml(path))
    except ValidationError as exc:
        raise ConfigurationError(f"invalid policy in {path}: {exc}") from exc


def load_context(assets_file: Path | None, iocs_file: Path | None) -> Context:
    """Load assets and identities (YAML) and indicators (JSON) into a :class:`Context`."""
    context = Context()
    try:
        if assets_file is not None:
            data = _read_yaml(assets_file)
            for raw in data.get("assets", []):  # type: ignore[attr-defined]
                asset = Asset.model_validate(raw)
                host = normalize_host(asset.name)
                if host is None:
                    raise ValueError(f"invalid asset name {asset.name!r}")
                context.assets[host] = asset
            for raw in data.get("identities", []):  # type: ignore[attr-defined]
                identity = Identity.model_validate(raw)
                user = normalize_user(identity.name)
                if user is None:
                    raise ValueError(f"invalid identity {identity.name!r}")
                context.identities[user] = identity
        if iocs_file is not None:
            try:
                raw_iocs = json.loads(iocs_file.read_text(encoding="utf-8"))["indicators"]
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise ConfigurationError(f"cannot read indicators from {iocs_file}: {exc}") from exc
            for raw in raw_iocs:
                indicator = Indicator.model_validate(raw)
                value = {"ip": normalize_ip, "domain": normalize_domain, "hash": normalize_hash}[
                    indicator.type
                ](indicator.value)
                if value is None:
                    raise ValueError(f"invalid {indicator.type} indicator {indicator.value!r}")
                context.indicators[f"{indicator.type}:{value}"] = indicator
    except (ValidationError, ValueError, TypeError, AttributeError) as exc:
        raise ConfigurationError(f"invalid context data: {exc}") from exc
    return context
