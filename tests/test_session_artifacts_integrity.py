import json
import os
import pytest
from pathlib import Path
from bughunter.core.session import SessionManager


def test_session_manager_trust_boundary_documented():
    doc = SessionManager.__doc__ or ""
    assert "tamper" in doc.lower()
    # Must not claim protection against attacker rewriting both data and hash
    assert "does not protect against" in doc.lower() or "not tamper-proofing" in doc.lower() or "privilege" in doc.lower()


def test_session_state_missing_hash_anchor_fails(tmp_path):
    sm = SessionManager(tmp_path)
    state = sm.create("localhost")
    sess_id = state["session_id"]
    
    # Delete hash anchor
    hash_file = sm.path(sess_id) / "state.sha256"
    hash_file.unlink()
    
    with pytest.raises(ValueError, match="integrity check failed"):
        sm.load(sess_id)


def test_session_save_storage_failure_rollback(tmp_path, monkeypatch):
    sm = SessionManager(tmp_path)
    state = sm.create("localhost")
    sess_id = state["session_id"]
    
    # Save a modification successfully first
    state["custom_key"] = "original_value"
    sm.save(state)
    assert sm.load(sess_id)["custom_key"] == "original_value"
    
    # Now simulate a storage failure during writing state.sha256
    real_atomic = sm._atomic
    def fail_on_sha256(path, data):
        if path.name == "state.sha256" and state.get("custom_key") == "broken_value":
            raise OSError("simulated storage failure (disk full)")
        return real_atomic(path, data)
        
    monkeypatch.setattr(sm, "_atomic", fail_on_sha256)
    
    state["custom_key"] = "broken_value"
    with pytest.raises(OSError, match="simulated storage failure"):
        sm.save(state)
        
    # The session state must NOT be left with broken_value in state.json while having original hash,
    # or corrupted. It must roll back to original_value and still pass integrity check!
    restored = sm.load(sess_id)
    assert restored["custom_key"] == "original_value"


def test_session_artifact_lifecycle_and_integrity(tmp_path):
    sm = SessionManager(tmp_path)
    state = sm.create("10.0.0.1")
    sess_id = state["session_id"]
    
    # Save text artifact
    art_path = sm.save_artifact(sess_id, "endpoints.txt", "http://10.0.0.1/api\nhttp://10.0.0.1/login\n")
    assert art_path.exists()
    assert (art_path.parent / "endpoints.txt.sha256").exists()
    
    # Load artifact
    content = sm.load_artifact(sess_id, "endpoints.txt", as_text=True)
    assert "http://10.0.0.1/api" in content
    assert sm.verify_artifact(sess_id, "endpoints.txt") is True
    
    # List artifacts
    artifacts = sm.list_artifacts(sess_id)
    assert "endpoints.txt" in artifacts
    assert "endpoints.txt.sha256" not in artifacts
    
    # Tampering with artifact must fail load
    art_path.write_text("tampered content")
    assert sm.verify_artifact(sess_id, "endpoints.txt") is False
    with pytest.raises(ValueError, match="integrity check failed"):
        sm.load_artifact(sess_id, "endpoints.txt")


def test_session_artifact_directory_traversal_blocked(tmp_path):
    sm = SessionManager(tmp_path)
    state = sm.create("localhost")
    sess_id = state["session_id"]
    
    with pytest.raises(ValueError, match="invalid artifact name"):
        sm.save_artifact(sess_id, "../../etc/passwd", "evil")
        
    with pytest.raises(ValueError, match="invalid artifact name"):
        sm.load_artifact(sess_id, "../state.json")
