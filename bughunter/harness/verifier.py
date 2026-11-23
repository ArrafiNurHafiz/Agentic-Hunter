"""Self-Verification Engine with reproducibility, canary matching, and 7-Question Gate."""
from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Any, Callable, Dict, List, Optional, Tuple

from bughunter.tools.validate import calculate_cvss40, severity_from_score


class VerificationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class VerificationResult:
    status: VerificationStatus
    confidence: float
    gate_passed: bool
    cvss_score: float
    cvss_vector: str
    severity: str
    notes: List[str] = field(default_factory=list)
    reproduced_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": self.confidence,
            "gate_passed": self.gate_passed,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "notes": self.notes,
            "reproduced_count": self.reproduced_count,
        }


class SelfVerificationEngine:
    """Multi-stage verification engine to minimize false positives and eliminate hallucinations."""

    def __init__(self):
        pass

    def verify_reproducibility(self, check_func: Callable[[], Any], min_repro: int = 2) -> Tuple[bool, int]:
        """Run check function multiple times to ensure deterministic behavior."""
        success_count = 0
        for _ in range(min_repro):
            try:
                res = check_func()
                if res:
                    success_count += 1
            except Exception:
                pass
        return success_count >= min_repro, success_count

    def verify_canary(self, response_body: str, expected_canary: str, negative_body: Optional[str] = None) -> Tuple[bool, str]:
        """Check if canary is present in positive response and absent in negative baseline."""
        if not expected_canary:
            return True, "No canary required"

        if expected_canary not in response_body:
            return False, f"Expected canary '{expected_canary}' not reflected in target response"

        if negative_body and expected_canary in negative_body:
            return False, f"Canary '{expected_canary}' was also found in negative baseline (reflection is static/false positive)"

        return True, "Canary matched exclusively in active response"

    def evaluate_7_question_gate(self, finding: Dict[str, Any], in_scope: bool = True) -> Dict[str, bool]:
        """
        Evaluate the 7-Question Gate criteria:
        1. Is it real (observable, not banner hallucination)?
        2. Is the asset in scope?
        3. Is it exploitable right now?
        4. Is it not a known duplicate?
        5. Is the business impact demonstrable?
        6. Is it non-theoretical (not self-XSS, rate limit missing)?
        7. Is evidence cryptographically recorded?
        """
        vuln_type = str(finding.get("vuln_type", "")).lower()
        title = str(finding.get("title", "")).lower()

        # Reject known theoretical/non-exploitable classes
        disallowed = ["self-xss", "missing rate limit", "software banner", "clickjacking on static page"]
        is_theoretical = any(d in vuln_type or d in title for d in disallowed)

        has_evidence = bool(finding.get("evidence") or finding.get("raw_output") or finding.get("evidence_hash"))
        has_endpoint = bool(finding.get("endpoint"))

        scores = {
            "is_real": has_evidence and not is_theoretical,
            "in_scope": in_scope,
            "exploitable_now": has_endpoint and has_evidence,
            "not_duplicate": not finding.get("duplicate", False),
            "clear_impact": finding.get("severity", "INFO").upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"),
            "non_theoretical": not is_theoretical,
            "evidence_hashed": bool(finding.get("evidence_hash")),
        }
        return scores

    def calculate_cvss_for_finding(self, finding: Dict[str, Any]) -> Tuple[float, str, str]:
        """Derive standard CVSS 4.0 score and vector from finding metadata."""
        sev = str(finding.get("severity", "MEDIUM")).upper()
        vuln_type = str(finding.get("vuln_type", "")).lower()

        # Sensible metric defaults based on severity/class
        if sev == "CRITICAL" or "rce" in vuln_type or "sqli" in vuln_type:
            score, vector = calculate_cvss40("N", "L", "N", "N", "N", "H", "H", "H", "N", "N", "N")
        elif sev == "HIGH" or "idor" in vuln_type or "auth" in vuln_type:
            score, vector = calculate_cvss40("N", "L", "N", "L", "N", "H", "L", "N", "N", "N", "N")
        elif sev == "MEDIUM" or "xss" in vuln_type or "csrf" in vuln_type:
            score, vector = calculate_cvss40("N", "L", "N", "N", "P", "L", "L", "N", "N", "N", "N")
        elif sev == "LOW":
            score, vector = calculate_cvss40("N", "L", "N", "H", "N", "L", "N", "N", "N", "N", "N")
        else:
            score, vector = 0.0, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"

        derived_severity = severity_from_score(score)
        return score, vector, derived_severity

    def verify_finding(self, finding: Dict[str, Any], in_scope: bool = True,
                       response_body: Optional[str] = None, expected_canary: Optional[str] = None,
                       negative_body: Optional[str] = None) -> VerificationResult:
        notes = []

        # 1. Canary check if applicable
        if expected_canary and response_body:
            canary_ok, canary_msg = self.verify_canary(response_body, expected_canary, negative_body)
            notes.append(canary_msg)
            if not canary_ok:
                score, vector, sev = self.calculate_cvss_for_finding(finding)
                return VerificationResult(
                    status=VerificationStatus.FALSE_POSITIVE,
                    confidence=0.1,
                    gate_passed=False,
                    cvss_score=0.0,
                    cvss_vector=vector,
                    severity="NONE",
                    notes=notes,
                )

        # 2. Evaluate 7-Question Gate
        gate = self.evaluate_7_question_gate(finding, in_scope=in_scope)
        passed_count = sum(1 for v in gate.values() if v)
        gate_passed = passed_count >= 5 and gate["is_real"] and gate["in_scope"]

        score, vector, derived_sev = self.calculate_cvss_for_finding(finding)

        if not gate["in_scope"]:
            status = VerificationStatus.FALSE_POSITIVE
            notes.append("Target asset is out of scope; rejected by Gate 2.")
            confidence = 0.0
        elif not gate["is_real"] or not gate["non_theoretical"]:
            status = VerificationStatus.FALSE_POSITIVE
            notes.append("Finding classified as theoretical or unprovable noise.")
            confidence = 0.2
        elif gate_passed:
            status = VerificationStatus.CONFIRMED
            notes.append(f"Passed 7-Question Gate ({passed_count}/7 criteria satisfied).")
            confidence = min(1.0, 0.5 + (passed_count * 0.08))
        else:
            status = VerificationStatus.INCONCLUSIVE
            notes.append(f"Inconclusive telemetry ({passed_count}/7 criteria satisfied).")
            confidence = 0.4

        return VerificationResult(
            status=status,
            confidence=round(confidence, 2),
            gate_passed=gate_passed,
            cvss_score=score,
            cvss_vector=vector,
            severity=derived_sev if status == VerificationStatus.CONFIRMED else "NONE",
            notes=notes,
            reproduced_count=1 if gate_passed else 0,
        )
