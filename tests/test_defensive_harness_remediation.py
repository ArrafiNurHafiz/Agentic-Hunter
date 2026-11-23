import json
import pytest

from bughunter.harness.remediation import get_remediation_advice, sanitize_finding_for_advisory
from bughunter.cli import attack_command


def test_sanitize_finding_strips_raw_evidence_and_secrets():
    raw_finding = {
        "finding_id": "fnd-123",
        "vuln_class": "SQL Injection",
        "tech_stack": ["PHP", "PostgreSQL"],
        "cwe": "CWE-89",
        "endpoint": "http://user:pass@localhost:8000/orders?id=123&token=secret-token",
        "raw_request": "GET /orders?id=123&token=secret-token HTTP/1.1\r\nAuthorization: Bearer my-secret-jwt\r\n\r\n",
        "raw_response": "HTTP/1.1 500 Internal Error\r\nSet-Cookie: session=secret-sess\r\n\r\nDatabase query failed",
        "raw_evidence": {"secret_field": "12345"},
    }

    sanitized = sanitize_finding_for_advisory(raw_finding)

    # Must contain defensive metadata
    assert sanitized["vuln_class"] == "SQL Injection"
    assert "PHP" in sanitized["tech_stack"]
    assert sanitized["cwe"] == "CWE-89"

    # Must NOT contain raw credentials, raw requests, raw responses, or raw evidence
    dumped = json.dumps(sanitized)
    assert "pass" not in sanitized.get("endpoint", "")
    assert "secret-token" not in dumped
    assert "my-secret-jwt" not in dumped
    assert "secret-sess" not in dumped
    assert "raw_request" not in sanitized
    assert "raw_response" not in sanitized
    assert "raw_evidence" not in sanitized


def test_remediation_advisor_sends_only_sanitized_metadata_to_brain():
    captured_prompts = []

    class MockBrain:
        available = True

        def chat(self, system, user):
            captured_prompts.append({"system": system, "user": user})
            return "Use parameterized queries / PDO prepared statements."

    finding = {
        "vuln_class": "SQL Injection",
        "tech_stack": ["PHP", "PDO"],
        "endpoint": "http://localhost:8000/api/search?q=test&token=secret-bearer-999",
        "raw_request": "GET /api/search... Authorization: Bearer secret-bearer-999",
        "raw_response": "SQL Syntax Error...",
    }

    advice = get_remediation_advice(MockBrain(), finding)
    assert "parameterized" in advice.lower() or "pdo" in advice.lower()

    assert len(captured_prompts) == 1
    prompt_text = captured_prompts[0]["user"] + " " + captured_prompts[0]["system"]

    # Verify no raw evidence or secret tokens leaked to brain prompt
    assert "secret-bearer-999" not in prompt_text
    assert "raw_request" not in prompt_text
    assert "raw_response" not in prompt_text


def test_remediation_advisor_deterministic_fallback_when_brain_offline():
    finding = {
        "vuln_class": "Reflected XSS",
        "tech_stack": ["Laravel", "Blade"],
    }
    advice = get_remediation_advice(None, finding)
    assert "encode" in advice.lower() or "context-aware" in advice.lower() or "escape" in advice.lower() or "xss" in advice.lower()


def test_attack_command_plan_generation_dry_run():
    class MockArgs:
        target = "http://localhost:8000"
        session_id = None
        scope = None
        dry_run = True
        profile = "active"
        phase = None

    attack_command.run(MockArgs())
