"""A real model client (`T4-07`).

**This is the only package in the project that may reach the network.** It is
`NETWORKED_AGENT`, and it is a **separate package** on purpose (`DEC-11`): the
agent runtime in `src/dpi_agents/` stays `OFFLINE_CORE`, so the code that reads a
capture is structurally unable to phone home. That is the mirror image of the
rule the safety suite already enforces for the core \u2014 *a core that transitively
loads an HTTP client is offline in name only* \u2014 and the risk here is the same
failure with the arrows reversed: an agent that can reach the network can be
*told* to by whatever it read in a capture.

**The API shape is OpenAI-compatible**, because most providers speak it and so
does a local server, and the base URL is configurable \u2014 so the choice is not
baked in. **No new dependency**: the standard library's `urllib`, in a thread,
because the call is blocking and the model port is async.

**`temperature=0`**, because the design's rule is that anything producing a
verdict must be reproducible. It is not a guarantee \u2014 a hosted model is not
deterministic whatever the temperature \u2014 but it is the difference between a
verdict that can be compared with the last run's and one that cannot.

**The configuration is the operator's**: the key, the base URL and the model name
come from the environment, because the model choice is a *cost* decision and the
cost is theirs.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any

from dpi_agents.model import Model, ModelMessage, ModelReply, ModelRequest, ModelUsage, ToolCall

__all__ = [
    "ModelClientError",
    "ModelSettings",
    "OpenAiCompatibleModel",
    "settings_from_environment",
]

#: The environment variables the client's configuration comes from.
ENV_API_KEY = "DPI_MODEL_API_KEY"
ENV_BASE_URL = "DPI_MODEL_BASE_URL"
ENV_MODEL_NAME = "DPI_MODEL_NAME"

#: Where the chat API lives, when the operator does not say.
DEFAULT_BASE_URL = "https://api.openai.com/v1"


class ModelClientError(RuntimeError):
    """The model could not be reached, or would not answer.

    Carries the provider's own message, because a client that says "the request
    failed" tells an operator nothing they can act on.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class ModelSettings:
    """How to reach the model."""

    api_key: str
    model: str
    base_url: str = DEFAULT_BASE_URL
    timeout_seconds: float = 120.0
    #: The sampling temperature. Zero, because a verdict must be reproducible.
    temperature: float = 0.0

    def __post_init__(self) -> None:
        if not self.api_key.strip():
            raise ValueError("the API key is empty")
        if not self.model.strip():
            raise ValueError("the model name is empty")


def settings_from_environment(environ: Mapping[str, str] | None = None) -> ModelSettings:
    """The configuration from the environment.

    Raises `ModelClientError` when the key is missing \u2014 the run is opt-in, and
    "no key" is a *skip with a reason*, not a silent success.
    """
    env = os.environ if environ is None else environ
    api_key = env.get(ENV_API_KEY, "").strip()
    if not api_key:
        raise ModelClientError(
            f"{ENV_API_KEY} is not set, so there is no model to run. The quality run is "
            "opt-in: without a key there is nothing to measure, and a skip that reads as "
            "a pass is not a measurement."
        )
    model = env.get(ENV_MODEL_NAME, "").strip()
    if not model:
        raise ModelClientError(
            f"{ENV_MODEL_NAME} is not set. The model is the operator's choice, because it "
            "is a cost decision, and the client will not pick one for them."
        )
    return ModelSettings(
        api_key=api_key,
        model=model,
        base_url=env.get(ENV_BASE_URL, DEFAULT_BASE_URL).strip() or DEFAULT_BASE_URL,
    )


def _tool_payload(tool: Mapping[str, Any]) -> dict[str, Any]:
    """One tool in the provider's shape.

    The MCP tool schema is `{name, description, inputSchema}`; the OpenAI shape
    is `{type: "function", function: {name, description, parameters}}`. The
    translation is here, so the port keeps one vocabulary (`D-16`).
    """
    schema = tool.get("inputSchema")
    return {
        "type": "function",
        "function": {
            "name": tool.get("name", ""),
            "description": tool.get("description", ""),
            "parameters": schema if isinstance(schema, dict) else {"type": "object"},
        },
    }


def _message_payload(message: ModelMessage) -> dict[str, Any]:
    """One message in the provider's shape."""
    if message.role == "tool":
        return {
            "role": "tool",
            "content": message.content,
            "tool_call_id": message.name or "",
        }
    return {"role": message.role, "content": message.content}


def build_request(request: ModelRequest, settings: ModelSettings) -> dict[str, Any]:
    """The JSON body of a chat completion.

    A pure function, so the shape of what goes to the provider is testable
    without a provider \u2014 and without a key.
    """
    body: dict[str, Any] = {
        "model": settings.model,
        "temperature": settings.temperature,
        "messages": [
            {"role": "system", "content": request.system},
            *(_message_payload(message) for message in request.messages),
        ],
    }
    if request.tools:
        body["tools"] = [_tool_payload(tool) for tool in request.tools]
        body["tool_choice"] = "auto"
    if request.max_output_tokens:
        body["max_tokens"] = request.max_output_tokens
    return body


def parse_response(payload: Mapping[str, Any]) -> ModelReply:
    """The provider's answer, as a `ModelReply`.

    The first choice is taken, and the refusal case is explicit: a model that
    declines to answer is not a model that answered with nothing.
    """
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ModelClientError("the provider returned no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ModelClientError("the provider returned a choice that is not an object")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ModelClientError("the provider returned a choice with no message")

    tool_calls: list[ToolCall] = []
    for call in message.get("tool_calls") or []:
        if not isinstance(call, dict):
            continue
        function = call.get("function")
        if not isinstance(function, dict):
            continue
        raw_arguments = function.get("arguments") or "{}"
        try:
            arguments = json.loads(raw_arguments)
        except json.JSONDecodeError:
            arguments = {}
        if not isinstance(arguments, dict):
            arguments = {}
        tool_calls.append(
            ToolCall(name=str(function.get("name", "")), arguments=arguments)
        )

    usage_raw = payload.get("usage")
    usage = ModelUsage()
    if isinstance(usage_raw, dict):
        usage = ModelUsage(
            input_tokens=int(usage_raw.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage_raw.get("completion_tokens", 0) or 0),
        )

    return ModelReply(
        text=str(message.get("content") or ""),
        tool_calls=tuple(tool_calls),
        usage=usage,
        stop_reason=str(first.get("finish_reason") or "end_turn"),
    )


class OpenAiCompatibleModel(Model):
    """A `Model` that talks to an OpenAI-compatible chat API.

    The only implementation in the project that touches the network, and it is
    in the only package that is allowed to.

    It declares that it implements the `Model` port rather than merely
    satisfying it structurally: the relationship is then checked by the type
    checker, and a method that drifts from the port's signature is an error
    rather than a runtime surprise.
    """

    def __init__(self, settings: ModelSettings) -> None:
        self._settings = settings

    @property
    def settings(self) -> ModelSettings:
        """How this client is configured."""
        return self._settings

    async def complete(self, request: ModelRequest) -> ModelReply:
        """One completion.

        The call is blocking, so it runs in a thread: the model port is async,
        and blocking the event loop for the length of a model call would stop
        the server answering anything else \u2014 including the cancellation that
        would have ended the wait.
        """
        body = build_request(request, self._settings)
        return await asyncio.to_thread(self._post, body)

    def _post(self, body: Mapping[str, Any]) -> ModelReply:
        """The blocking call, with the provider's errors kept intact."""
        url = f"{self._settings.base_url.rstrip('/')}/chat/completions"
        data = json.dumps(body).encode("utf-8")
        http_request = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._settings.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                http_request, timeout=self._settings.timeout_seconds
            ) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise ModelClientError(
                f"the model returned HTTP {exc.code} for {url}: {body_text[:400]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ModelClientError(f"could not reach the model at {url}: {exc.reason}") from exc

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ModelClientError(f"the model returned something that is not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ModelClientError("the model returned JSON that is not an object")
        return parse_response(payload)
