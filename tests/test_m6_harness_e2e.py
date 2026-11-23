import json
from pathlib import Path
import pytest
from bughunter.core.session import SessionManager
from bughunter.core.scope import ContinuousScope
from bughunter.harness.orchestrator import HarnessOrchestrator
from bughunter import __main__


def test_harness_e2e_dry_run_local_target(tmp_path):
    sm = SessionManager(tmp_path)
    state = sm.create("http://192.168.1.50:8000")
    sess_id = state["session_id"]

    scope = ContinuousScope.default_for_target("http://192.168.1.50:8000")
    orchestrator = HarnessOrchestrator(
        session_id=sess_id,
        target="http://192.168.1.50:8000",
        scope=scope,
        dry_run=True,
        profile="active",
        session_manager=sm,
    )

    # Inject a simulated finding into memory for validation & reporting verification
    orchestrator.memory.add_finding(
        title="IDOR on order details",
        severity="HIGH",
        vuln_type="IDOR",
        endpoint="http://192.168.1.50:8000/api/orders/42",
        raw_evidence={"request": "GET /api/orders/42", "response": {"id": 42}},
        verified=False,
    )

    final_state = orchestrator.run()
    assert final_state["session_id"] == sess_id

    # Verify reports were created
    session_dir = sm.path(sess_id)
    reports_dir = session_dir / "reports"
    assert (reports_dir / "report.json").exists()
    assert (reports_dir / "report.md").exists()

    rep_json = json.loads((reports_dir / "report.json").read_text())
    assert rep_json["target"] == "http://192.168.1.50:8000"
    assert len(rep_json["findings"]) == 1
    assert rep_json["findings"][0]["title"] == "IDOR on order details"
    assert rep_json["findings"][0]["status"] == "CONFIRMED"


def test_harness_differential_retesting(tmp_path):
    sm = SessionManager(tmp_path)
    state = sm.create("http://10.0.0.15:3000")
    sess_id = state["session_id"]

    # Seed state with one confirmed finding
    state["findings"] = [
        {
            "finding_id": "fnd_test123",
            "title": "SQLi in search query",
            "status": "CONFIRMED",
            "endpoint": "http://10.0.0.15:3000/search",
        }
    ]
    sm.save(state)

    orchestrator = HarnessOrchestrator(
        session_id=sess_id,
        target="http://10.0.0.15:3000",
        session_manager=sm,
        dry_run=False,
    )

    retest_result = orchestrator.retest()
    assert retest_result["session_id"] == sess_id
    assert len(retest_result["still_present"]) == 1
    assert retest_result["still_present"][0]["finding_id"] == "fnd_test123"

    retest_file = sm.path(sess_id) / "reports" / "retest_report.json"
    assert retest_file.exists()


def test_cli_retest_subcommand(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    sm = SessionManager(tmp_path / ".bughunter" / "sessions")
    state = sm.create("http://localhost:8080")
    sess_id = state["session_id"]
    state["findings"] = [{"finding_id": "f1", "title": "Bypass", "status": "CONFIRMED"}]
    sm.save(state)

    monkeypatch.setattr("sys.argv", ["bughunter", "retest", sess_id, "--dry-run"])
    __main__.main()

    out = capsys.readouterr().out
    assert sess_id in out
    data = json.loads(out)
    assert len(data["fixed"]) == 1
    assert data["fixed"][0]["title"] == "Bypass"
