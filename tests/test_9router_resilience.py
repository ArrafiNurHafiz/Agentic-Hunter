import json
import types
import pytest
from bughunter.brain import LLMClient, _parse_openai_compat_response
from bughunter.agent import _OpenAIToolClient


class _MockResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return json.loads(self.text) if self.text else {}


def test_parse_openai_compat_response_matrix():
    # 1. Standard JSON
    res = _parse_openai_compat_response(json.dumps({"choices": [{"message": {"content": "Hello"}}]}))
    assert res["choices"][0]["message"]["content"] == "Hello"

    # 2. Trailing data: [DONE]
    res2 = _parse_openai_compat_response(json.dumps({"choices": [{"message": {"content": "Hello"}}]}) + "\n\ndata: [DONE]\n")
    assert res2["choices"][0]["message"]["content"] == "Hello"

    # 3. SSE stream with delta chunks
    sse = (
        'data: {"choices": [{"delta": {"content": "Hello "}}]}\n\n'
        'data: {"choices": [{"delta": {"content": "world!"}}]}\n\n'
        'data: [DONE]\n'
    )
    res3 = _parse_openai_compat_response(sse)
    assert res3["choices"][0]["message"]["content"] == "Hello world!"

    # 4. Empty choices list
    res4 = _parse_openai_compat_response(json.dumps({"choices": []}))
    assert res4.get("choices") == []

    # 5. Error JSON payload
    res5 = _parse_openai_compat_response(json.dumps({"error": {"message": "Too Many Requests", "code": 429}}))
    assert res5.get("error", {}).get("code") == 429

    # 6. Empty text
    assert _parse_openai_compat_response("") == {}
    assert _parse_openai_compat_response("   \n ") == {}

    # 7. Truncated JSON
    assert _parse_openai_compat_response('{"choices": [{"message": {"content": "trun') == {}


def test_brain_chat_openai_compat_resilience(monkeypatch):
    client = LLMClient.__new__(LLMClient)
    client.available = True
    client.provider = "9router"
    client._api_base = "http://localhost:20128/v1"

    # Test SSE response handling in LLMClient
    sse_body = 'data: {"choices": [{"delta": {"content": "Streamed Answer"}}]}\n\ndata: [DONE]'
    client._http = types.SimpleNamespace(post=lambda *args, **kwargs: _MockResponse(sse_body))
    ans = client._chat_openai_compat("openai/gpt-4o", "sys", "usr", 100, 0.1)
    assert ans == "Streamed Answer"

    # Test empty choices list does not raise IndexError
    client._http = types.SimpleNamespace(post=lambda *args, **kwargs: _MockResponse(json.dumps({"choices": []})))
    assert client._chat_openai_compat("openai/gpt-4o", "sys", "usr", 100, 0.1) == ""

    # Test error object does not raise KeyError
    client._http = types.SimpleNamespace(post=lambda *args, **kwargs: _MockResponse(json.dumps({"error": {"message": "Rate limited"}})))
    assert client._chat_openai_compat("openai/gpt-4o", "sys", "usr", 100, 0.1) == ""

    # Test empty text does not raise JSONDecodeError
    client._http = types.SimpleNamespace(post=lambda *args, **kwargs: _MockResponse(""))
    assert client._chat_openai_compat("openai/gpt-4o", "sys", "usr", 100, 0.1) == ""

    # Test HTTP 404 provides actionable model deprecation hint
    client._http = types.SimpleNamespace(post=lambda *args, **kwargs: _MockResponse("Not Found", status_code=404))
    with pytest.raises(RuntimeError, match="retired/decommissioned"):
        client._chat_openai_compat("openai/gpt-4o", "sys", "usr", 100, 0.1)


def test_agent_openai_tool_client_resilience():
    tool_client = _OpenAIToolClient.__new__(_OpenAIToolClient)
    tool_client.base_url = "http://localhost:20128/v1"

    # SSE handling
    sse_body = 'data: {"choices": [{"message": {"content": "SSE Tool Response"}}]}\n\ndata: [DONE]'
    tool_client.session = types.SimpleNamespace(post=lambda *args, **kwargs: _MockResponse(sse_body))
    resp = tool_client.chat(model="openai/gpt-4o", messages=[{"role": "user", "content": "hi"}])
    assert resp["message"]["content"] == "SSE Tool Response"

    # Empty text
    tool_client.session = types.SimpleNamespace(post=lambda *args, **kwargs: _MockResponse(""))
    resp2 = tool_client.chat(model="openai/gpt-4o", messages=[{"role": "user", "content": "hi"}])
    assert resp2 == {"message": {}}
