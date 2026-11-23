"""Defensive remediation guidance generator using sanitized metadata only.

Trust and Privacy Boundary:
When communicating with Brain / 9Router, raw evidence, raw HTTP requests, raw
HTTP responses, authorization headers, and session tokens are STRICTLY FORBIDDEN.
Only high-level, sanitized metadata (vulnerability class, detected technologies,
CWE, and clean URL paths without credentials or secret tokens) may be provided.
"""
from typing import Any, Dict, List, Optional
import json
import urllib.parse

from bughunter.memory.redaction import redact_obj


_SENSITIVE_PARAM_KEYS = {
    "token", "api_key", "apikey", "secret", "password", "pass", "auth",
    "key", "session", "sess", "jwt", "bearer", "private", "credential",
}

_DETERMINISTIC_REMEDIATIONS = {
    "SQLI": (
        "Implement parameterized queries / prepared statements (e.g., PDO, ORM query builders). "
        "Never concatenate user input directly into SQL strings. Apply least privilege to database users."
    ),
    "XSS": (
        "Apply context-aware output encoding (HTML body, attributes, JavaScript context). "
        "Enable a strong Content-Security-Policy (CSP) and ensure modern templating engines auto-escape output."
    ),
    "IDOR": (
        "Enforce strict server-side authorization and tenant isolation checks before accessing any record. "
        "Verify that the authenticated user owns or has explicit permission for the requested object identifier."
    ),
    "SSRF": (
        "Validate and strictly allowlist target URLs, domains, and IP ranges. "
        "Block outbound requests to RFC 1918 private IPs and loopback in production, and disable following external redirects."
    ),
    "SSTI": (
        "Never pass untrusted user input directly into template engine evaluation functions. "
        "Use static template strings and pass input strictly as context variables with sandboxing enabled."
    ),
    "PATHTRAVERSAL": (
        "Sanitize file paths using basename extraction and canonical path verification (`realpath`). "
        "Ensure resolved paths remain strictly within the designated safe storage directory."
    ),
}


def sanitize_finding_for_advisory(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Extract and sanitize defensive metadata from a finding for remediation analysis.

    Strips all raw request, response, and evidence payloads to prevent sensitive data leaks.
    """
    raw_endpoint = finding.get("endpoint") or finding.get("url") or ""
    clean_endpoint = _sanitize_url(raw_endpoint)

    vuln_class = (
        finding.get("vuln_class")
        or finding.get("vuln_type")
        or finding.get("title")
        or "General Security Flaw"
    )

    tech_stack = finding.get("tech_stack") or []
    if isinstance(tech_stack, str):
        tech_stack = [tech_stack]

    cwe = finding.get("cwe")
    cvss_vector = finding.get("cvss_vector")

    sanitized = {
        "vuln_class": vuln_class,
        "tech_stack": list(tech_stack),
        "endpoint": clean_endpoint,
    }
    if cwe:
        sanitized["cwe"] = cwe
    if cvss_vector:
        sanitized["cvss_vector"] = cvss_vector

    return redact_obj(sanitized)


def _sanitize_url(url: str) -> str:
    if not url:
        return ""
    try:
        parsed = urllib.parse.urlsplit(url)
        # Strip userinfo (username:password)
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"

        # Sanitize query parameters
        if parsed.query:
            query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            sanitized_pairs = []
            for k, v in query_pairs:
                if any(s in k.lower() for s in _SENSITIVE_PARAM_KEYS):
                    sanitized_pairs.append((k, "[REDACTED]"))
                else:
                    sanitized_pairs.append((k, v))
            clean_query = urllib.parse.urlencode(sanitized_pairs)
        else:
            clean_query = ""

        clean = urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, clean_query, ""))
        return clean
    except Exception:
        return "[REDACTED_URL]"


def get_remediation_advice(brain: Any, finding: Dict[str, Any]) -> str:
    """Produce actionable remediation guidance from sanitized metadata only."""
    sanitized = sanitize_finding_for_advisory(finding)
    vuln_class = sanitized.get("vuln_class", "")

    if brain and getattr(brain, "available", False):
        try:
            system_prompt = (
                "You are an application security advisor. Provide clear, defensive remediation "
                "guidance for developers to fix the specified vulnerability class. Never generate "
                "exploit payloads or attack instructions. Output developer guidance only."
            )
            user_prompt = (
                f"Vulnerability Class: {sanitized.get('vuln_class')}\n"
                f"Technology Stack: {json.dumps(sanitized.get('tech_stack', []))}\n"
                f"CWE: {sanitized.get('cwe', 'N/A')}\n"
                f"Endpoint / Component: {sanitized.get('endpoint', 'N/A')}\n\n"
                "Provide secure coding recommendations and remediation steps for the development team."
            )
            reply = brain.chat(system=system_prompt, user=user_prompt)
            if reply and reply.strip():
                redacted_reply = redact_obj(reply)
                return redacted_reply if isinstance(redacted_reply, str) else str(redacted_reply)
        except Exception:
            pass

    # Deterministic fallback
    for key, text in _DETERMINISTIC_REMEDIATIONS.items():
        if key in vuln_class.upper().replace(" ", "").replace("-", ""):
            return text

    return (
        "Implement strict input validation, enforce authorization checks at the data layer, "
        "and follow the principle of least privilege."
    )
