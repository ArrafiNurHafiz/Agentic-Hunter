import pytest
from bughunter.core.session import SessionManager
from bughunter.harness.memory import HarnessMemory, WorkingMemory, ContextCompactor
from bughunter.harness.recovery import LoopBreaker, LoopDetectedError, CircuitBreakerMonitor, TargetUnresponsiveError, StateCheckpoint


def test_harness_memory_three_layers():
    mem = HarnessMemory(target="http://192.168.1.50:8000")
    mem.working.add_note("Discovered Laravel framework")
    mem.working.add_hypothesis("IDOR on /api/orders/{id}")
    mem.working.detected_tech.extend(["PHP 8.2", "Laravel 10"])

    mem.add_observation("httpx", "Host is live, returned HTTP 200")
    mem.add_observation("katana", "Found 12 endpoints")

    evidence = {"request": "GET /api/orders/1", "response": {"order_id": 1, "owner": "admin"}}
    rec = mem.add_finding(
        title="BOLA / IDOR on order endpoint",
        severity="HIGH",
        vuln_type="IDOR",
        endpoint="/api/orders/1",
        raw_evidence=evidence,
        verified=True,
    )

    assert rec.finding_id.startswith("fnd_")
    assert len(rec.evidence_hash) == 64
    assert rec.verified is True

    context = mem.get_prompt_context()
    assert "192.168.1.50:8000" in context
    assert "Laravel" in context
    assert "BOLA / IDOR" in context


def test_context_compactor_length_limit():
    compactor = ContextCompactor(max_chars=200)
    working = WorkingMemory(target="http://test.local")
    for i in range(50):
        working.add_note(f"Note entry number {i} with long description text repeating")
    compacted = compactor.compact(working, [], [])
    assert len(compacted) <= 350
    assert "older context summarized" in compacted


def test_loop_breaker_triggers_error():
    breaker = LoopBreaker(warn_at=3, break_at=5)
    action = "run_api_fuzz"
    args = {"endpoint": "/api/v1/orders"}

    # Calls 1 and 2
    w1, b1 = breaker.record_and_check(action, args)
    assert not w1 and not b1
    w2, b2 = breaker.record_and_check(action, args)
    assert not w2 and not b2

    # Call 3: warning
    w3, b3 = breaker.record_and_check(action, args)
    assert w3 and not b3

    # Call 4
    w4, b4 = breaker.record_and_check(action, args)
    assert w4 and not b4

    # Call 5: must break (raises LoopDetectedError)
    with pytest.raises(LoopDetectedError, match="stalled"):
        breaker.record_and_check(action, args)


def test_circuit_breaker_monitor():
    monitor = CircuitBreakerMonitor(max_consecutive_5xx=3)
    monitor.record_status(200)
    monitor.record_status(500)
    monitor.record_status(502)
    with pytest.raises(TargetUnresponsiveError, match="Circuit breaker triggered"):
        monitor.record_status(503)


def test_state_checkpoint_updates(tmp_path):
    sm = SessionManager(tmp_path)
    state = sm.create("192.168.1.50")
    sess_id = state["session_id"]

    checkpoint = StateCheckpoint(sm)
    updated = checkpoint.update_phase(sess_id, phase_number=1, new_status="completed")
    phase1 = next(p for p in updated["phases"] if p["number"] == 1)
    assert phase1["status"] == "completed"

    checkpoint.record_findings(sess_id, [{"id": "f1", "title": "Test Vuln"}])
    reloaded = checkpoint.load_state(sess_id)
    assert len(reloaded["findings"]) == 1
    assert reloaded["findings"][0]["title"] == "Test Vuln"
