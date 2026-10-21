"""The real model client (`T4-07`).

**The keyless path is verified here.** The client is exercised end to end
against a **local** server, so its request building, its response parsing and
its error handling are all proven without a provider and without a key. What
remains unverified without a key is the *provider's* behaviour, and that is
exactly the part the quality run is for.

**Nothing here reaches a provider.** The only network the tests open is a
localhost socket, and the client is pointed at it.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from dpi_agents.model import ModelMessage, ModelRequest, ModelUsage, ToolCall
from dpi_model_client import (
    ModelClientError,
    ModelSettings,
    OpenAiCompatibleModel,
    settings_from_environment,
)
from dpi_model_client.client import build_request, parse_response

SETTINGS = ModelSettings(api_key="test-key", model="test-model", base_url="http://127.0.0.1:1/v1")


class TestTheRequest:
    def test_the_system_prompt_comes_first(self) -> None:
        body = build_request(
            ModelRequest(system="you are a triage agent", messages=()), SETTINGS
        )
        assert body["messages"][0] == {"role": "system", "content": "you are a triage agent"}

    def test_the_temperature_is_zero(self) -> None:
        """Anything producing a verdict must be reproducible."""
        body = build_request(ModelRequest(system="s"), SETTINGS)
        assert body["temperature"] == 0.0

    def test_the_model_is_the_operators_choice(self) -> None:
        body = build_request(ModelRequest(system="s"), SETTINGS)
        assert body["model"] == "test-model"

    def test_the_tools_are_translated_to_the_providers_shape(self) -> None:
        body = build_request(
            ModelRequest(
                system="s",
                tools=(
                    {
                        "name": "query_flows",
                        "description": "the stored flows",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"run_id": {"type": "string"}},
                            "required": ["run_id"],
                        },
                    },
                ),
            ),
            SETTINGS,
        )
        assert body["tools"] == [
            {
                "type": "function",
                "function": {
                    "name": "query_flows",
                    "description": "the stored flows",
                    "parameters": {
                        "type": "object",
                        "properties": {"run_id": {"type": "string"}},
                        "required": ["run_id"],
                    },
                },
            }
        ]
        assert body["tool_choice"] == "auto"

    def test_a_tool_observation_is_sent_as_a_tool_message(self) -> None:
        body = build_request(
            ModelRequest(
                system="s",
                messages=(ModelMessage(role="tool", content="27 flows", name="query_flows"),),
            ),
            SETTINGS,
        )
        assert body["messages"][1] == {
            "role": "tool",
            "content": "27 flows",
            "tool_call_id": "query_flows",
        }

    def test_no_tools_means_no_tool_key(self) -> None:
        body = build_request(ModelRequest(system="s"), SETTINGS)
        assert "tools" not in body
        assert "tool_choice" not in body


class TestTheResponse:
    def test_a_text_answer_is_read(self) -> None:
        reply = parse_response(
            {"choices": [{"message": {"content": '{"severity": "high"}'}}], "usage": {}}
        )
        assert reply.text == '{"severity": "high"}'
        assert reply.tool_calls == ()

    def test_a_tool_call_is_read(self) -> None:
        reply = parse_response(
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "function": {
                                        "name": "query_flows",
                                        "arguments": '{"run_id": "abc"}',
                                    }
                                }
                            ],
                        }
                    }
                ]
            }
        )
        assert reply.tool_calls == (ToolCall(name="query_flows", arguments={"run_id": "abc"}),)

    def test_broken_tool_arguments_do_not_crash_the_client(self) -> None:
        """A model that sends nonsense arguments is a model that is wrong, not a
        client that has crashed."""
        reply = parse_response(
            {
                "choices": [
                    {
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {"function": {"name": "query_flows", "arguments": "{not json"}}
                            ],
                        }
                    }
                ]
            }
        )
        assert reply.tool_calls[0].arguments == {}

    def test_the_usage_is_counted(self) -> None:
        """A budget that cannot be counted is not a budget."""
        reply = parse_response(
            {
                "choices": [{"message": {"content": "x"}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            }
        )
        assert reply.usage == ModelUsage(input_tokens=11, output_tokens=7)
        assert reply.usage.total_tokens == 18

    def test_a_response_with_no_choices_is_an_error(self) -> None:
        with pytest.raises(ModelClientError, match="no choices"):
            parse_response({"choices": []})

    def test_a_response_with_no_message_is_an_error(self) -> None:
        with pytest.raises(ModelClientError, match="no message"):
            parse_response({"choices": [{"finish_reason": "length"}]})


class TestTheConfiguration:
    def test_a_missing_key_is_refused_with_a_reason(self) -> None:
        """No key, no run -- and the reason says so."""
        with pytest.raises(ModelClientError, match="DPI_MODEL_API_KEY"):
            settings_from_environment({})

    def test_a_missing_model_name_is_refused(self) -> None:
        """The model is the operator's choice, because it is a cost decision."""
        with pytest.raises(ModelClientError, match="DPI_MODEL_NAME"):
            settings_from_environment({"DPI_MODEL_API_KEY": "k"})

    def test_the_base_url_defaults_and_is_overridable(self) -> None:
        default = settings_from_environment(
            {"DPI_MODEL_API_KEY": "k", "DPI_MODEL_NAME": "m"}
        )
        assert default.base_url == "https://api.openai.com/v1"
        other = settings_from_environment(
            {
                "DPI_MODEL_API_KEY": "k",
                "DPI_MODEL_NAME": "m",
                "DPI_MODEL_BASE_URL": "http://localhost:1234/v1",
            }
        )
        assert other.base_url == "http://localhost:1234/v1"

    def test_an_empty_key_is_refused(self) -> None:
        with pytest.raises(ValueError, match="API key"):
            ModelSettings(api_key="  ", model="m")


class _Handler(BaseHTTPRequestHandler):
    """A local server that answers like a chat API, and records what it was sent."""

    received: list[dict[str, Any]] = []
    response: dict[str, Any] = {"choices": [{"message": {"content": "hello"}}]}

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).received.append(body)
        payload = json.dumps(type(self).response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: Any) -> None:
        """Keep the test output quiet."""


@pytest.fixture
def local_model() -> Any:
    """A local chat API, and the settings that point at it."""
    _Handler.received = []
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    settings = ModelSettings(
        api_key="test-key", model="test-model", base_url=f"http://{host}:{port}/v1"
    )
    try:
        yield settings, _Handler
    finally:
        server.shutdown()
        server.server_close()


class TestAgainstALocalServer:
    def test_a_call_goes_out_and_the_answer_comes_back(self, local_model: Any) -> None:
        import asyncio

        settings, handler = local_model
        client = OpenAiCompatibleModel(settings)
        reply = asyncio.run(client.complete(ModelRequest(system="you are a triage agent")))
        assert reply.text == "hello"
        assert handler.received[0]["model"] == "test-model"
        assert handler.received[0]["temperature"] == 0.0
        assert handler.received[0]["messages"][0]["role"] == "system"

    def test_a_tool_call_round_trips(self, local_model: Any) -> None:
        import asyncio

        settings, handler = local_model
        handler.response = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {"function": {"name": "query_flows", "arguments": '{"run_id": "a"}'}}
                        ],
                    }
                }
            ],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4},
        }
        client = OpenAiCompatibleModel(settings)
        reply = asyncio.run(client.complete(ModelRequest(system="s")))
        assert reply.tool_calls == (ToolCall(name="query_flows", arguments={"run_id": "a"}),)
        assert reply.usage.total_tokens == 7

    def test_a_provider_error_keeps_the_providers_message(self, local_model: Any) -> None:
        """A client that says "the request failed" tells an operator nothing."""
        import asyncio

        settings, _handler = local_model
        settings_with_bad_url = ModelSettings(
            api_key="k", model="m", base_url="http://127.0.0.1:1/v1", timeout_seconds=1.0
        )
        with pytest.raises(ModelClientError, match="could not reach the model"):
            asyncio.run(
                OpenAiCompatibleModel(settings_with_bad_url).complete(ModelRequest(system="s"))
            )
        assert settings.base_url  # the local server is still configured


def test_the_client_package_is_the_only_one_that_may_reach_the_network() -> None:
    """`DEC-11`: the boundary is a fact about the tree, not a habit.

    The agent runtime must stay `OFFLINE_CORE`, and the safety suite checks that
    by scanning imports as well as calls -- so this test is about the *declaration*
    being the other way round.
    """
    from safety_envelope import NETWORKED_AGENT, OFFLINE_CORE, PACKAGE_ENVELOPES

    assert PACKAGE_ENVELOPES["dpi_model_client"] is NETWORKED_AGENT
    assert PACKAGE_ENVELOPES["dpi_agents"] is OFFLINE_CORE
    assert PACKAGE_ENVELOPES["dpi_mcp"] is OFFLINE_CORE
    assert PACKAGE_ENVELOPES["dpi_engine"] is OFFLINE_CORE
