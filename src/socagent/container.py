"""Composition root: builds an :class:`IRService` from :class:`Settings`."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import httpx

from socagent.agents.summary import LLMSummaryWriter, SummaryWriter, TemplateSummaryWriter
from socagent.config import Settings, load_context, load_policy
from socagent.db import ActionStore, AlertStore, AuditLog, Database, IncidentStore
from socagent.errors import ConfigurationError
from socagent.executor import ActionService, Connector, DryRunConnector, WebhookConnector
from socagent.providers import AnthropicChatClient, JsonClient, LLMClient, OpenAIChatClient
from socagent.service import IRService


def _json_client(settings: Settings, http_client: httpx.Client | None) -> JsonClient:
    return JsonClient(
        http_client or httpx.Client(timeout=settings.http_timeout_seconds),
        attempts=settings.retry_attempts,
        min_wait=settings.retry_min_wait,
        max_wait=settings.retry_max_wait,
    )


def _summary_writer(settings: Settings, client: JsonClient) -> SummaryWriter:
    llm: LLMClient
    if settings.llm_provider == "none":
        return TemplateSummaryWriter()
    if settings.llm_provider == "openai":
        if settings.openai_api_key is None:
            raise ConfigurationError("SOCAGENT_OPENAI_API_KEY must be set when llm_provider=openai")
        llm = OpenAIChatClient(
            client,
            api_key=settings.openai_api_key,
            model=settings.openai_chat_model,
            base_url=settings.openai_base_url,
        )
    else:
        if settings.anthropic_api_key is None:
            raise ConfigurationError(
                "SOCAGENT_ANTHROPIC_API_KEY must be set when llm_provider=anthropic"
            )
        llm = AnthropicChatClient(
            client,
            api_key=settings.anthropic_api_key,
            model=settings.anthropic_model,
            max_tokens=settings.anthropic_max_tokens,
            base_url=settings.anthropic_base_url,
        )
    return LLMSummaryWriter(llm)


def build_service(
    settings: Settings,
    *,
    http_client: httpx.Client | None = None,
    clock: Callable[[], datetime] | None = None,
    connector: Connector | None = None,
    summary_writer: SummaryWriter | None = None,
) -> IRService:
    """Assemble the dependency graph and open the database.

    Execution is a dry run unless ``execution_mode`` is ``live`` and a connector URL is set.

    Raises:
        ConfigurationError: If files or provider credentials are missing or invalid.
    """
    policy = load_policy(settings.policy_file)
    context = load_context(settings.assets_file, settings.iocs_file)
    client = _json_client(settings, http_client)
    if connector is None:
        if settings.execution_mode == "live":
            assert settings.connector_url is not None  # enforced by Settings validation
            connector = WebhookConnector(client, settings.connector_url)
        else:
            connector = DryRunConnector()
    db = Database(settings.db_path)
    actions = ActionStore(db)
    audit = AuditLog(db, clock)
    return IRService(
        settings,
        db,
        AlertStore(db),
        IncidentStore(db),
        actions,
        audit,
        ActionService(
            db, actions, audit, policy, connector, mode=settings.execution_mode, clock=clock
        ),
        context,
        policy,
        summary_writer or _summary_writer(settings, client),
        clock,
    )
