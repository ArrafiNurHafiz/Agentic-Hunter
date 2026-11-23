import subprocess
import sys

import pytest

from bughunter.core.session import SessionManager
from bughunter.core.state_machine import PhaseStatus, new_phases


def test_transitions():
    phases = new_phases()
    assert len(phases) == 10
    phase = phases[0]
    with pytest.raises(ValueError):
        phase.transition(PhaseStatus.COMPLETED)
    phase.transition(PhaseStatus.RUNNING)
    phase.transition(PhaseStatus.COMPLETED)
    with pytest.raises(ValueError):
        phase.transition(PhaseStatus.RUNNING)


def test_session_integrity(tmp_path):
    manager = SessionManager(tmp_path)
    state = manager.create('localhost')
    assert manager.load(state['session_id']) == state
    (manager.path(state['session_id']) / 'state.json').write_text('{}')
    with pytest.raises(ValueError, match='integrity'):
        manager.load(state['session_id'])


def test_attack_help():
    result = subprocess.run([sys.executable, '-m', 'bughunter', 'attack', '--help'], capture_output=True, text=True)
    assert result.returncode == 0
    assert '--dry-run' in result.stdout
