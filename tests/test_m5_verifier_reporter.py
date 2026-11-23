import json
from pathlib import Path
import pytest
from bughunter.harness.verifier import SelfVerificationEngine, VerificationStatus
from bughunter.harness.reporter import HarnessReportGenerator


def test_verifier_confirmed_finding():
    engine = SelfVerificationEngine()
    finding = {
        "title": "BOLA / IDOR on order API",
        "vuln_type": "IDOR",
        "endpoint": "http://192.168.1.50:8000/api/orders/2",
        "severity": "HIGH",
        "evidence_hash": "a" * 64,
        "evidence": {"response": "Order data"},
    }
    result = engine.verify_finding(finding, in_scope=True)
    assert result.status == VerificationStatus.CONFIRMED
    assert result.gate_passed is True
    assert result.cvss_score > 0.0
    assert result.severity == "HIGH"
    assert "Passed 7-Question Gate" in result.notes[0]


def test_verifier_canary_matching():
    engine = SelfVerificationEngine()
    canary = "bh_canary_test123"
    positive_resp = f"<html><body>Hello <{canary}></body></html>"
    negative_resp = "<html><body>Hello visitor</body></html>"

    ok, msg = engine.verify_canary(positive_resp, canary, negative_resp)
    assert ok is True

    # False positive: canary exists in negative baseline too
    fp_neg = f"<html><{canary}></html>"
    ok_fp, msg_fp = engine.verify_canary(positive_resp, canary, fp_neg)
    assert ok_fp is False
    assert "negative baseline" in msg_fp


def test_verifier_rejects_out_of_scope_and_theoretical():
    engine = SelfVerificationEngine()
    finding = {
        "title": "Self-XSS on search bar",
        "vuln_type": "self-xss",
        "endpoint": "http://192.168.1.50:8000/search",
        "severity": "LOW",
        "evidence": {"raw": "test"},
    }
    # Theoretical vuln rejected
    res = engine.verify_finding(finding, in_scope=True)
    assert res.status == VerificationStatus.FALSE_POSITIVE

    # Out of scope rejected
    finding2 = {
        "title": "SQLi on external server",
        "vuln_type": "SQLi",
        "endpoint": "http://external.test/api",
        "severity": "CRITICAL",
        "evidence": {"raw": "test"},
        "evidence_hash": "b" * 64,
    }
    res2 = engine.verify_finding(finding2, in_scope=False)
    assert res2.status == VerificationStatus.FALSE_POSITIVE


def test_harness_report_generation(tmp_path):
    reporter = HarnessReportGenerator(session_id="sess_20261123_test", target="http://192.168.1.50:8000")
    state = {"session_id": "sess_20261123_test", "target": "http://192.168.1.50:8000"}
    findings = [
        {
            "status": "CONFIRMED",
            "title": "IDOR on /api/orders/2",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
            "endpoint": "http://192.168.1.50:8000/api/orders/2",
            "evidence_hash": "c" * 64,
            "description": "Unauthorized order viewing",
            "confidence": 0.95,
        }
    ]

    json_path, md_path = reporter.save_reports(tmp_path, state, findings)
    assert json_path.exists()
    assert md_path.exists()

    json_content = json.loads(json_path.read_text())
    assert json_content["summary"]["confirmed"] == 1
    assert json_content["target"] == "http://192.168.1.50:8000"

    md_content = md_path.read_text()
    assert "# SECURITY ASSESSMENT REPORT" in md_content
    assert "[HIGH] IDOR on /api/orders/2" in md_content
    assert "CVSS 4.0 Score:" in md_content
    assert "Forensic Evidence Hash (SHA-256):" in md_content
