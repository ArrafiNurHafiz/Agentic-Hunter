"""Context-aware non-destructive diagnostic payload generator."""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import uuid

from bughunter.harness.safety_gate import DeterministicSafetyGate, SecurityPolicyViolationError


@dataclass
class DiagnosticPayload:
    vuln_class: str
    payload: str
    negative_payload: Optional[str] = None
    expected_canary: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "payload": self.payload,
            "negative_payload": self.negative_payload,
            "expected_canary": self.expected_canary,
            "description": self.description,
        }


class AIPayloadEngine:
    """Generates strictly non-destructive diagnostic probes vetted by DeterministicSafetyGate."""

    def __init__(self, brain=None):
        self.brain = brain
        self.gate = DeterministicSafetyGate()

    def generate_sqli_boolean_probe(self) -> DiagnosticPayload:
        true_payload = "' AND 8419=8419--"
        false_payload = "' AND 8419=8420--"
        self.gate.check_or_raise(true_payload)
        self.gate.check_or_raise(false_payload)
        return DiagnosticPayload(
            vuln_class="SQLi",
            payload=true_payload,
            negative_payload=false_payload,
            description="Boolean-based inference pair without data extraction",
        )

    def generate_sqli_time_probe(self, db_type: str = "generic") -> DiagnosticPayload:
        if db_type.lower() == "postgres":
            payload = "'; SELECT pg_sleep(2)--"
        elif db_type.lower() == "mysql":
            payload = "' OR sleep(2)--"
        else:
            payload = "' OR sleep(2)--"
        self.gate.check_or_raise(payload)
        return DiagnosticPayload(
            vuln_class="SQLi",
            payload=payload,
            description="Controlled non-destructive 2s sleep probe",
        )

    def generate_xss_canary_probe(self) -> DiagnosticPayload:
        canary = f"bh_canary_{uuid.uuid4().hex[:8]}"
        payload = f"\"><{canary}>"
        self.gate.check_or_raise(payload)
        return DiagnosticPayload(
            vuln_class="XSS",
            payload=payload,
            expected_canary=canary,
            description="Harmless reflected HTML canary tag",
        )

    def generate_ssti_probe(self) -> DiagnosticPayload:
        payload = "{{7*7}}"
        self.gate.check_or_raise(payload)
        return DiagnosticPayload(
            vuln_class="SSTI",
            payload=payload,
            expected_canary="49",
            description="Math evaluation probe 7*7 -> 49",
        )

    def generate_path_traversal_probe(self) -> DiagnosticPayload:
        payload = "../../../../robots.txt"
        self.gate.check_or_raise(payload)
        return DiagnosticPayload(
            vuln_class="PathTraversal",
            payload=payload,
            expected_canary="User-agent:",
            description="Safe public static file traversal (robots.txt)",
        )

    def generate_probe(self, vuln_class: str, context: Optional[Dict[str, Any]] = None) -> DiagnosticPayload:
        vc = vuln_class.upper()
        if "SQL" in vc:
            return self.generate_sqli_boolean_probe()
        elif "XSS" in vc:
            return self.generate_xss_canary_probe()
        elif "SSTI" in vc:
            return self.generate_ssti_probe()
        elif "TRAVERSAL" in vc or "LFI" in vc:
            return self.generate_path_traversal_probe()
        else:
            canary = f"bh_diag_{uuid.uuid4().hex[:6]}"
            return DiagnosticPayload(
                vuln_class=vuln_class,
                payload=canary,
                expected_canary=canary,
                description=f"Generic diagnostic canary for {vuln_class}",
            )
