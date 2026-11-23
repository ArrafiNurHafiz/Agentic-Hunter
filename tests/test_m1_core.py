import json
from pathlib import Path
import pytest
from bughunter.core.state_machine import PhaseStatus, PhaseContract, new_phases, TRANSITIONS
from bughunter.core.session import SessionManager
from bughunter.core.scope import ContinuousScope, ScopeDecision
from bughunter.core.policy_engine import PolicyEngine
from bughunter.core.executor import run_command
from bughunter.cli import attack_command


def test_state_machine_phases_and_transitions():
    phases = new_phases()
    assert len(phases) == 10
    names = [p.name for p in phases]
    assert "scope" in names
    assert "retesting" in names

    p = phases[0]
    assert p.status == PhaseStatus.PENDING
    p.transition(PhaseStatus.RUNNING)
    assert p.status == PhaseStatus.RUNNING
    p.transition(PhaseStatus.COMPLETED)
    assert p.status == PhaseStatus.COMPLETED

    # Cannot transition back to RUNNING from COMPLETED
    with pytest.raises(ValueError):
        p.transition(PhaseStatus.RUNNING)


def test_session_creation_and_tamper_detection(tmp_path):
    sm = SessionManager(tmp_path)
    state = sm.create("192.168.1.50")
    sess_id = state["session_id"]
    assert sess_id.startswith("sess_")
    assert state["target"] == "192.168.1.50"
    assert len(state["phases"]) == 10

    loaded = sm.load(sess_id)
    assert loaded["session_id"] == sess_id
    assert loaded["target"] == "192.168.1.50"

    # Tamper with state.json
    state_file = sm.path(sess_id) / "state.json"
    state_file.write_text('{"tampered": true}')
    with pytest.raises(ValueError, match="integrity check failed"):
        sm.load(sess_id)


def test_zero_private_ip_blocking():
    # RFC 1918 addresses and localhost must be allowed by default
    private_targets = [
        "10.0.0.15",
        "172.16.5.20",
        "192.168.1.50",
        "127.0.0.1",
        "localhost",
    ]
    for target in private_targets:
        scope = ContinuousScope.default_for_target(target)
        decision = scope.validate_action(f"http://{target}/api/test", method="GET")
        assert decision == ScopeDecision.ALLOW, f"Private target {target} should be allowed"

    # Out of scope must still be blocked
    scope = ContinuousScope.default_for_target("192.168.1.50")
    assert scope.validate_action("http://192.168.1.51/test") == ScopeDecision.BLOCK_OUT_OF_SCOPE
    assert scope.validate_action("http://google.com/test") == ScopeDecision.BLOCK_OUT_OF_SCOPE


def test_attack_command_status_and_validation(tmp_path, monkeypatch, capsys):
    sm = SessionManager(tmp_path)
    state = sm.create("192.168.1.50")
    sess_id = state["session_id"]

    class MockArgs:
        target = "status"
        session_id = sess_id
        scope = None
        dry_run = False
        profile = "active"
        phase = None

    monkeypatch.setattr(attack_command, "SessionManager", lambda root=None: sm)
    attack_command.run(MockArgs())
    captured = capsys.readouterr().out
    assert sess_id in captured
    assert "192.168.1.50" in captured
