import json
import socket
import sys

import pytest

from bughunter import __main__
from bughunter.core.session import SessionManager
from bughunter.memory.evidence import EvidenceStore


@pytest.fixture
def saved_session(monkeypatch, tmp_path):
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    manager = SessionManager()
    state = manager.create('http://localhost:8000/?token=private-target-token')
    session_id = state['session_id']
    store = EvidenceStore(manager.path(session_id) / 'evidence')
    store.capture(kind='observation', finding_id='fnd-example',
                  request={'headers': {'Authorization': 'Bearer private-request-token'}})
    return manager.path(session_id), session_id, store


@pytest.mark.parametrize(('format_name', 'suffix'), [('json', 'json'), ('markdown', 'md')])
def test_report_exports_verified_metadata_offline(monkeypatch, saved_session, format_name, suffix):
    directory, session_id, store = saved_session

    def unexpected_network(*args, **kwargs):
        pytest.fail('session report attempted network access')

    monkeypatch.setattr(socket, 'socket', unexpected_network)
    monkeypatch.setattr(sys, 'argv', ['bughunter', 'report', session_id, '--format', format_name])
    __main__.main()
    report = (directory / 'reports' / f'ASSESSMENT_REPORT.{suffix}').read_text()
    record = store.read_verified()[0]
    assert record['digest'] in report
    assert 'private-target-token' not in report
    assert 'private-request-token' not in report
    if format_name == 'json':
        parsed = json.loads(report)
        assert len(parsed['phases']) == 10
        assert parsed['evidence'][0]['finding_id'] == 'fnd-example'


def test_session_report_rejects_corrupt_evidence(monkeypatch, saved_session):
    directory, session_id, store = saved_session
    store.path.write_text(store.path.read_text().replace('fnd-example', 'fnd-altered'))
    monkeypatch.setattr(sys, 'argv', ['bughunter', 'report', session_id])
    with pytest.raises(SystemExit, match='evidence chain integrity check failed'):
        __main__.main()
    assert not list((directory / 'reports').iterdir())
