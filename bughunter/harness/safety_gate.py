"""Deterministic safety gate and banned keyword filter for AI Agent Harness.

Enforces Non-Destructive by Design and Data Minimization. Rejects any payload
attempting database mutation, data dumping, or OS command execution.
"""
import re
from typing import Optional, Tuple


class SecurityPolicyViolationError(ValueError):
    """Raised when an action or payload violates the deterministic safety policy."""
    pass


class DeterministicSafetyGate:
    # Strictly banned keywords & regex patterns that can cause damage or data mutation
    BANNED_PATTERNS = [
        # SQL destructive mutations
        re.compile(r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|ALTER\s+TABLE)\b", re.IGNORECASE),
        re.compile(r"\b(DELETE\s+FROM|UPDATE\s+[\w`\"]+\s+SET|INSERT\s+INTO)\b", re.IGNORECASE),
        re.compile(r"\b(INTO\s+OUTFILE|INTO\s+DUMPFILE|LOAD_FILE)\b", re.IGNORECASE),
        re.compile(r"\b(XP_CMDSHELL|SP_EXECUTESQL)\b", re.IGNORECASE),

        # Destructive OS commands & reverse shells
        re.compile(r"\b(rm\s+-[rf]{1,2}|shutdown|reboot|poweroff)\b", re.IGNORECASE),
        re.compile(r"(curl\s+.*\|\s*(?:bash|sh|zsh)|wget\s+.*\|\s*(?:bash|sh|zsh))", re.IGNORECASE),
        re.compile(r"\b(bash\s+-i|/bin/sh|/bin/bash|mkfifo|nc\s+-[elp])\b", re.IGNORECASE),
        re.compile(r"\b(kill\s+-9|pkill|killall)\b", re.IGNORECASE),
        re.compile(r"\b(chmod\s+777|chown\s+root)\b", re.IGNORECASE),

        # Sensitive OS secrets / shadow dumping
        re.compile(r"(/etc/shadow|/etc/master\.passwd|SYSTEM32\\config\\SAM)", re.IGNORECASE),

        # Fork bomb / DoS
        re.compile(r"(\:\(\)\{\s*\:\|\:\&\s*\}\;\:|dd\s+if=/dev/zero)", re.IGNORECASE),
    ]

    @classmethod
    def validate_payload(cls, payload: str) -> Tuple[bool, Optional[str]]:
        """
        Verify if the given payload conforms to the non-destructive policy.
        Returns: (is_safe, error_reason_if_unsafe)
        """
        if not payload or not isinstance(payload, str):
            return True, None

        for pattern in cls.BANNED_PATTERNS:
            match = pattern.search(payload)
            if match:
                matched_text = match.group(0)
                return False, f"Banned destructive pattern detected: '{matched_text}'"

        return True, None

    @classmethod
    def check_or_raise(cls, payload: str) -> None:
        """Raise SecurityPolicyViolationError if payload is unsafe."""
        is_safe, reason = cls.validate_payload(payload)
        if not is_safe:
            raise SecurityPolicyViolationError(reason)
