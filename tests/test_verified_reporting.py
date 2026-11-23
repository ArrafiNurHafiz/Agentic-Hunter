import json
import socket
import sys
import pytest

from bughunter import __main__
from bughunter.core.session import SessionManager
from bughunter.memory.evidence import EvidenceStore
from bughunter.phases.p09_reporting import write_session_report


def test_reporting_downgrades_unsupported_verdicts(monkeypatch, tmp_path):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    sm = SessionManager(tmp_path)
    state = sm.create("http://localhost:8000")
    sess_id = state["session_id"]
    
    # State claims a finding is CONFIRMED with CRITICAL severity, but evidence store has NO records for it
    state["findings"] = [
        {
            "finding_id": "fnd-unverified-sqli",
            "title": "SQL Injection in Search",
            "status": "CONFIRMED",
            "severity": "CRITICAL",
            "endpoint": "http://localhost:8000/search?q=test",
        }
    ]
    sm.save(state)
    
    report_file = write_session_report(sess_id, "json", manager=sm)
    data = json.loads(report_file.read_text())
    
    # The finding must NOT be marked CONFIRMED because there is no verified evidence!
    finding = next(f for f in data["findings"] if f["finding_id"] == "fnd-unverified-sqli")
    assert finding["status"] != "CONFIRMED"
    assert finding["status"] in ("INCONCLUSIVE", "UNVERIFIED")
    assert "unverified" in finding.get("validation_note", "").lower() or "evidence" in finding.get("validation_note", "").lower()


def test_reporting_preserves_confirmed_verdict_with_verified_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    sm = SessionManager(tmp_path)
    state = sm.create("http://localhost:8000")
    sess_id = state["session_id"]
    
    # Capture verified evidence for this finding
    store = EvidenceStore(sm.path(sess_id) / "evidence")
    rec = store.capture(
        kind="validation",
        finding_id="fnd-proven-idor",
        status="CONFIRMED",
        url="http://localhost:8000/api/users/2",
        observation="Canary reflected and unauthorized object returned",
    )
    
    state["findings"] = [
        {
            "finding_id": "fnd-proven-idor",
            "title": "IDOR on user endpoint",
            "status": "CONFIRMED",
            "severity": "HIGH",
            "endpoint": "http://localhost:8000/api/users/2",
        }
    ]
    sm.save(state)
    
    report_file = write_session_report(sess_id, "json", manager=sm)
    data = json.loads(report_file.read_text())
    
    finding = next(f for f in data["findings"] if f["finding_id"] == "fnd-proven-idor")
    assert finding["status"] == "CONFIRMED"
    assert rec["digest"] in finding.get("evidence_digests", [])


def test_reporting_redacts_sensitive_values_in_findings_and_urls(monkeypatch, tmp_path):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    sm = SessionManager(tmp_path)
    state = sm.create("http://localhost:8000/?api_key=super-secret-key-12345")
    sess_id = state["session_id"]
    
    store = EvidenceStore(sm.path(sess_id) / "evidence")
    store.capture(
        kind="observation",
        finding_id="fnd-1",
        request={"headers": {"Authorization": "Bearer sensitive-auth-token-999"}},
        observation="Found secret session_id=topsecret1234 in response",
    )
    
    state["findings"] = [
        {
            "finding_id": "fnd-1",
            "title": "Token leak in header",
            "endpoint": "http://localhost:8000/?api_key=super-secret-key-12345",
            "description": "Password leaked: Password123!",
        }
    ]
    sm.save(state)
    
    md_file = write_session_report(sess_id, "markdown", manager=sm)
    md_content = md_file.read_text()
    
    assert "super-secret-key-12345" not in md_content
    assert "sensitive-auth-token-999" not in md_content
    assert "topsecret1234" not in md_content
    assert "Password123!" not in md_content
