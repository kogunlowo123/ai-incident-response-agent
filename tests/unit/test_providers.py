"""Tests for the HTTP helper, model clients and logging."""

from __future__ import annotations

import json
import logging

import httpx
import pytest
from pydantic import SecretStr

from socagent.errors import ProviderError, TransientProviderError
from socagent.logging_setup import JsonFormatter, RedactingTextFormatter, configure_logging
from socagent.providers import AnthropicChatClient, OpenAIChatClient
from tests.conftest import json_client


class TestJsonClient:
    def test_success(self) -> None:
        client = json_client(lambda r: httpx.Response(200, json={"ok": 1}))
        assert client.request("GET", "https://x.example/a") == {"ok": 1}

    def test_retries_transient_status_then_succeeds(self) -> None:
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            return (
                httpx.Response(503) if len(calls) == 1 else httpx.Response(200, json={"ok": True})
            )

        assert json_client(handler, attempts=3).request("GET", "https://x.example") == {"ok": True}
        assert len(calls) == 2

    def test_gives_up_after_attempts(self) -> None:
        with pytest.raises(TransientProviderError):
            json_client(lambda r: httpx.Response(500), attempts=2).request(
                "GET", "https://x.example"
            )

    def test_transport_errors_are_transient(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route")

        with pytest.raises(TransientProviderError):
            json_client(handler, attempts=2).request("GET", "https://x.example")

    def test_client_errors_are_not_retried_and_redact_the_body(self) -> None:
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            return httpx.Response(401, text="bad key sk-" + "z" * 30)

        with pytest.raises(ProviderError) as info:
            json_client(handler, attempts=3).request("GET", "https://x.example")
        assert len(calls) == 1 and "z" * 30 not in str(info.value)

    def test_non_json_body(self) -> None:
        with pytest.raises(ProviderError):
            json_client(lambda r: httpx.Response(200, text="<html>")).request(
                "GET", "https://x.example"
            )


class TestChatClients:
    def test_openai_request_and_response(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, json={"choices": [{"message": {"content": " hello "}}]})

        llm = OpenAIChatClient(
            json_client(handler),
            api_key=SecretStr("k1"),
            model="m",
            base_url="https://o.example/v1/",
        )
        assert llm.complete("sys", "usr") == "hello"
        body = json.loads(seen[0].content)
        assert seen[0].url == "https://o.example/v1/chat/completions"
        assert (
            seen[0].headers["authorization"] == "Bearer k1"
            and body["messages"][1]["content"] == "usr"
        )

    def test_openai_bad_shape(self) -> None:
        llm = OpenAIChatClient(
            json_client(lambda r: httpx.Response(200, json={"nope": 1})),
            api_key=SecretStr("k"),
            model="m",
        )
        with pytest.raises(ProviderError, match="shape"):
            llm.complete("s", "u")

    def test_anthropic_request_and_response(self) -> None:
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(
                200,
                json={
                    "content": [
                        {"type": "text", "text": "a"},
                        {"type": "tool_use"},
                        {"type": "text", "text": "b"},
                    ]
                },
            )

        llm = AnthropicChatClient(
            json_client(handler), api_key=SecretStr("k2"), model="m", max_tokens=50
        )
        assert llm.complete("sys", "usr") == "ab"
        assert (
            seen[0].headers["x-api-key"] == "k2" and json.loads(seen[0].content)["max_tokens"] == 50
        )

    @pytest.mark.parametrize(
        "payload", [{"content": []}, {"content": [{"type": "tool_use"}]}, {"other": 1}]
    )
    def test_anthropic_bad_or_empty(self, payload: dict[str, object]) -> None:
        llm = AnthropicChatClient(
            json_client(lambda r: httpx.Response(200, json=payload)),
            api_key=SecretStr("k"),
            model="m",
        )
        with pytest.raises(ProviderError):
            llm.complete("s", "u")


class TestLogging:
    def _record(self, message: str, **extra: object) -> logging.LogRecord:
        record = logging.LogRecord("socagent.t", logging.WARNING, __file__, 1, message, None, None)
        record.__dict__.update(extra)
        return record

    def test_json_formatter_redacts_message_and_extras(self) -> None:
        line = JsonFormatter().format(
            self._record("token=abcd1234efgh", detail="password=Sup3rSecret", count=3)
        )
        payload = json.loads(line)
        assert "abcd1234efgh" not in line and "Sup3rSecret" not in line and payload["count"] == 3

    def test_json_formatter_includes_redacted_exceptions(self) -> None:
        try:
            raise ValueError("password=Sup3rSecret")
        except ValueError:
            import sys

            record = self._record("failed")
            record.exc_info = sys.exc_info()
        assert "Sup3rSecret" not in JsonFormatter().format(record)

    def test_text_formatter_redacts(self) -> None:
        assert "Sup3rSecret" not in RedactingTextFormatter("%(message)s").format(
            self._record("password=Sup3rSecret")
        )

    @pytest.mark.parametrize("as_json", [True, False])
    def test_configure_logging_is_idempotent(self, as_json: bool) -> None:
        root = logging.getLogger("socagent")
        before = list(root.handlers)
        try:
            configure_logging("INFO", json_output=as_json)
            configure_logging("INFO", json_output=as_json)
            assert len(root.handlers) <= len(before) + 1
        finally:
            root.handlers[:] = before
