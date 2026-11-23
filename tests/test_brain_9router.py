"""Tests for 9Router integration in Brain (LLMClient) and Agent (ReActAgent).

9Router is an open-source local AI gateway & model router running by default
at http://localhost:20128/v1 with an OpenAI-compatible REST API.
"""

import importlib
import json
import os
import sys
import types
import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

_ENV = (
    "BRAIN_PROVIDER", "BRAIN_MODEL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "XAI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY",
    "MOONSHOT_API_KEY", "MISTRAL_API_KEY", "TOGETHER_API_KEY",
    "CEREBRAS_API_KEY", "PERPLEXITY_API_KEY", "OPENROUTER_API_KEY",
    "ORCAROUTER_API_KEY", "FLUXION_API_KEY", "REQUESTY_API_KEY",
    "NINEROUTER_API_KEY", "NINEROUTER_BASE_URL", "ROUTER9_API_KEY",
    "ROUTER9_BASE_URL",
)


@pytest.fixture
def brain_module(monkeypatch):
    for env in _ENV:
        monkeypatch.delenv(env, raising=False)
    import brain
    importlib.reload(brain)
    return brain


class _Tracker:
    def __init__(self, available_provider: str | None = None):
        self.calls: list[str] = []
        self.available_provider = available_provider

    def bind(self, client):
        def _init(provider: str) -> None:
            self.calls.append(provider)
            client.available = provider == self.available_provider
        client._init_provider = _init


def test_9router_registered_in_maps(brain_module):
    LLMClient = brain_module.LLMClient
    assert LLMClient.DEFAULT_MODELS["9router"] == "openai/gpt-4o"
    assert LLMClient.PROVIDER_KEY_ENV["9router"] == "NINEROUTER_API_KEY"


def test_9router_key_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("NINEROUTER_API_KEY", "sk-9router-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="9router")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "9router"
    assert tracker.calls[0] == "9router"


def test_9router_base_url_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("NINEROUTER_BASE_URL", "http://localhost:20128/v1")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="9router")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "9router"
    assert tracker.calls[0] == "9router"


def test_9router_init_sets_api_base_default(brain_module, monkeypatch):
    monkeypatch.setenv("NINEROUTER_API_KEY", "sk-9router-key")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._http = None
    client.description = ""
    client.provider = "9router"

    brain_module.LLMClient._init_provider(client, "9router")

    assert client.available is True
    assert client._api_base == "http://localhost:20128/v1"
    assert "9router" in client.description.lower()
    assert brain_module.LLMClient.DEFAULT_MODELS["9router"] == "openai/gpt-4o"


def test_9router_init_sets_custom_base_url(brain_module, monkeypatch):
    monkeypatch.setenv("NINEROUTER_BASE_URL", "http://127.0.0.1:30000/v1/")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._http = None
    client.description = ""
    client.provider = "9router"

    brain_module.LLMClient._init_provider(client, "9router")

    assert client.available is True
    assert client._api_base == "http://127.0.0.1:30000/v1"


def test_9router_chat_dispatch(brain_module, monkeypatch):
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = True
    client.provider = "9router"
    client._api_base = "http://localhost:20128/v1"

    captured = {}

    class _MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        @property
        def text(self):
            return json.dumps(self.json())

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "VULN_CONFIRMED: IDOR in /api/v1/user",
                        }
                    }
                ]
            }

    class _MockSession:
        def post(self, url, data=None, timeout=None):
            captured["url"] = url
            captured["timeout"] = timeout
            captured["data"] = json.loads(data) if isinstance(data, str) else data
            return _MockResponse()

    client._http = _MockSession()
    reply = client.chat(model="openai/gpt-4o", system="You are an auditor", user="Audit this endpoint")

    assert reply == "VULN_CONFIRMED: IDOR in /api/v1/user"
    assert captured["url"] == "http://localhost:20128/v1/chat/completions"
    assert captured["timeout"] == 120
    assert captured["data"]["model"] == "openai/gpt-4o"
    assert captured["data"]["messages"][0]["role"] == "system"


def test_9router_chat_custom_timeout_and_reasoning_fallback(brain_module, monkeypatch):
    monkeypatch.setenv("BRAIN_TIMEOUT", "300")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = True
    client.provider = "9router"
    client._api_base = "http://localhost:20128/v1"

    captured = {}

    class _ReasoningResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        @property
        def text(self):
            return json.dumps(self.json())

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "reasoning_content": "Extracted from reasoning payload",
                        }
                    }
                ]
            }

    class _MockSession:
        def post(self, url, data=None, timeout=None):
            captured["timeout"] = timeout
            return _ReasoningResponse()

    client._http = _MockSession()
    reply = client.chat(model="Hermes", system="system", user="user")
    assert reply == "Extracted from reasoning payload"
    assert captured["timeout"] == 300


def test_9router_list_models_mock(brain_module):
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = True
    client.provider = "9router"
    client._api_base = "http://localhost:20128/v1"

    class _MockResponse:
        status_code = 200

        @property
        def text(self):
            return json.dumps(self.json())

        def json(self):
            return {
                "data": [
                    {"id": "kr/claude-sonnet-4.5"},
                    {"id": "openai/gpt-4o"},
                    {"id": "deepseek/deepseek-chat"},
                ]
            }

    class _MockSession:
        def get(self, url, timeout=None):
            return _MockResponse()

    client._http = _MockSession()
    models = client.list_models()

    assert "kr/claude-sonnet-4.5" in models
    assert "openai/gpt-4o" in models
    assert "deepseek/deepseek-chat" in models


def test_agent_openai_tool_client(monkeypatch):
    import agent

    client = agent._OpenAIToolClient(base_url="http://localhost:20128/v1", api_key="sk-test")

    captured = {}

    class _MockResponse:
        status_code = 200

        def raise_for_status(self):
            pass

        @property
        def text(self):
            return json.dumps(self.json())

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {
                                        "name": "run_recon",
                                        "arguments": "{\"max_urls\": 50}"
                                    }
                                }
                            ]
                        }
                    }
                ]
            }

    class _MockSession:
        headers = {}

        def post(self, url, json=None, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return _MockResponse()

        def get(self, url, timeout=None):
            resp = types.SimpleNamespace()
            resp.status_code = 200
            resp.json = lambda: {"data": [{"id": "model-1"}]}
            return resp

    client.session = _MockSession()

    res = client.chat(
        model="openai/gpt-4o",
        messages=[{"role": "user", "content": "Start hunt"}],
        tools=[{"type": "function", "function": {"name": "run_recon"}}],
    )

    assert "message" in res
    assert len(res["message"]["tool_calls"]) == 1
    assert res["message"]["tool_calls"][0]["function"]["name"] == "run_recon"
    assert captured["url"] == "http://localhost:20128/v1/chat/completions"
    assert captured["json"]["model"] == "openai/gpt-4o"
