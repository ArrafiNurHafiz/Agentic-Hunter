import json
import pytest
from pathlib import Path

from bughunter.core.session import SessionManager
from bughunter.memory.evidence import EvidenceStore, EvidenceError
from bughunter.phases.p10_retesting import compare_session_snapshots


def test_comparison_preserves_historical_snapshots(tmp_path):
    sm = SessionManager(tmp_path)
    state_a = sm.create("http://localhost:8000")
    sess_a = state_a["session_id"]
    state_b = sm.create("http://localhost:8000")
    sess_b = state_b["session_id"]

    store_a = EvidenceStore(sm.path(sess_a) / "evidence")
    store_a.capture(kind="finding", finding_id="fnd-1", url="http://localhost:8000/api/1")
    state_a["findings"] = [{"finding_id": "fnd-1", "title": "IDOR", "status": "CONFIRMED"}]
    sm.save(state_a)

    before_state_a = (sm.path(sess_a) / "state.json").read_bytes()
    before_ev_a = (sm.path(sess_a) / "evidence" / "evidence.jsonl").read_bytes()

    diff = compare_session_snapshots(sess_a, sess_b, manager=sm)

    # Historical files in Session A MUST remain completely unchanged!
    assert (sm.path(sess_a) / "state.json").read_bytes() == before_state_a
    assert (sm.path(sess_a) / "evidence" / "evidence.jsonl").read_bytes() == before_ev_a


def test_comparison_does_not_infer_fixed_from_data_variance_or_absence(tmp_path):
    sm = SessionManager(tmp_path)
    state_a = sm.create("http://localhost:8000")
    sess_a = state_a["session_id"]
    state_b = sm.create("http://localhost:8000")
    sess_b = state_b["session_id"]

    store_a = EvidenceStore(sm.path(sess_a) / "evidence")
    store_a.capture(kind="finding", finding_id="fnd-xss", url="http://localhost:8000/search?q=test")
    state_a["findings"] = [{"finding_id": "fnd-xss", "title": "XSS in search", "status": "CONFIRMED"}]
    sm.save(state_a)

    # In session B, no test was run on fnd-xss (absence of data)
    diff = compare_session_snapshots(sess_a, sess_b, manager=sm)
    item = next(i for i in diff["comparisons"] if i["finding_id"] == "fnd-xss")
    assert item["status"] != "Fixed"
    assert item["status"] == "Inconclusive"
    assert "absence" in item["rationale"].lower() or "unobserved" in item["rationale"].lower() or "not re-evaluated" in item["rationale"].lower()

    # Now simulate Session B having a different response body (data variance), but no proof of sanitization
    store_b = EvidenceStore(sm.path(sess_b) / "evidence")
    store_b.capture(
        kind="observation",
        finding_id="fnd-xss",
        url="http://localhost:8000/search?q=test",
        response={"status_code": 200, "body_differs": True},
        observation="Response length changed from 1024 to 2048 bytes",
    )
    diff2 = compare_session_snapshots(sess_a, sess_b, manager=sm)
    item2 = next(i for i in diff2["comparisons"] if i["finding_id"] == "fnd-xss")
    assert item2["status"] != "Fixed"
    assert item2["status"] == "Inconclusive"
    assert "difference" in item2["rationale"].lower() or "variance" in item2["rationale"].lower() or "insufficient" in item2["rationale"].lower()


def test_comparison_detects_still_present_and_regression(tmp_path):
    sm = SessionManager(tmp_path)
    state_a = sm.create("http://localhost:8000")
    sess_a = state_a["session_id"]
    state_b = sm.create("http://localhost:8000")
    sess_b = state_b["session_id"]

    store_a = EvidenceStore(sm.path(sess_a) / "evidence")
    store_a.capture(kind="finding", finding_id="fnd-1", url="http://localhost:8000/vuln1")
    store_a.capture(kind="finding", finding_id="fnd-2", url="http://localhost:8000/vuln2")
    state_a["findings"] = [
        {"finding_id": "fnd-1", "title": "Vuln 1", "status": "CONFIRMED"},
        {"finding_id": "fnd-2", "title": "Vuln 2", "status": "CONFIRMED"},
    ]
    sm.save(state_a)

    store_b = EvidenceStore(sm.path(sess_b) / "evidence")
    # Finding 1 still reproduces
    store_b.capture(
        kind="validation",
        finding_id="fnd-1",
        status="CONFIRMED",
        observation="Vulnerability still reproducible with canary reflection",
    )
    # Finding 2 triggered a regression (500 internal server error)
    store_b.capture(
        kind="validation",
        finding_id="fnd-2",
        status="REGRESSION",
        response={"status_code": 500},
        observation="Server returned 500 internal error on probe",
    )

    diff = compare_session_snapshots(sess_a, sess_b, manager=sm)
    item1 = next(i for i in diff["comparisons"] if i["finding_id"] == "fnd-1")
    item2 = next(i for i in diff["comparisons"] if i["finding_id"] == "fnd-2")

    assert item1["status"] == "Still Present"
    assert item2["status"] == "Regression"


def test_comparison_marks_fixed_only_with_verified_counter_evidence(tmp_path):
    sm = SessionManager(tmp_path)
    state_a = sm.create("http://localhost:8000")
    sess_a = state_a["session_id"]
    state_b = sm.create("http://localhost:8000")
    sess_b = state_b["session_id"]

    store_a = EvidenceStore(sm.path(sess_a) / "evidence")
    store_a.capture(kind="finding", finding_id="fnd-sqli", url="http://localhost:8000/api/items")
    state_a["findings"] = [{"finding_id": "fnd-sqli", "title": "SQLi in items", "status": "CONFIRMED"}]
    sm.save(state_a)

    # Session B has explicit verified counter-evidence showing input validation and safe handling
    store_b = EvidenceStore(sm.path(sess_b) / "evidence")
    store_b.capture(
        kind="validation",
        finding_id="fnd-sqli",
        status="RESOLVED",
        response={"status_code": 400},
        observation="Input validation safely rejected payload with 400 Bad Request; endpoint remains functional",
    )

    diff = compare_session_snapshots(sess_a, sess_b, manager=sm)
    item = next(i for i in diff["comparisons"] if i["finding_id"] == "fnd-sqli")
    assert item["status"] == "Fixed"


def test_comparison_rejects_corrupted_snapshots(tmp_path):
    sm = SessionManager(tmp_path)
    state_a = sm.create("http://localhost:8000")
    sess_a = state_a["session_id"]
    state_b = sm.create("http://localhost:8000")
    sess_b = state_b["session_id"]

    # Tamper with Session A state
    (sm.path(sess_a) / "state.json").write_text('{"tampered": true}')

    with pytest.raises(ValueError, match="integrity"):
        compare_session_snapshots(sess_a, sess_b, manager=sm)
