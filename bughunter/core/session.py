"""Persistent assessment sessions with atomic snapshots and integrity checks."""
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .state_machine import new_phases


class SessionManager:
    def __init__(self, root=None):
        self.root = Path(root or Path.home() / '.bughunter' / 'sessions')

    def path(self, session_id):
        if not re.fullmatch(r'sess_[A-Za-z0-9_-]+', session_id):
            raise ValueError('invalid session ID')
        return self.root / session_id

    def create(self, target):
        session_id = 'sess_' + datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_') + uuid4().hex[:8]
        directory = self.path(session_id)
        directory.mkdir(parents=True, exist_ok=False)
        for name in ('artifacts', 'evidence', 'reports'):
            (directory / name).mkdir()
        state = {'session_id': session_id, 'target': target,
                 'phases': [{'number': p.number, 'name': p.name, 'status': p.status.value} for p in new_phases()]}
        self.save(state)
        return state

    @staticmethod
    def _atomic(path, data):
        fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    def save(self, state):
        directory = self.path(state['session_id'])
        data = (json.dumps(state, indent=2, sort_keys=True) + '\n').encode()
        self._atomic(directory / 'state.json', data)
        self._atomic(directory / 'state.sha256', (hashlib.sha256(data).hexdigest() + '\n').encode())

    def load(self, session_id):
        directory = self.path(session_id)
        data = (directory / 'state.json').read_bytes()
        expected = (directory / 'state.sha256').read_text().strip()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('session state integrity check failed')
        state = json.loads(data)
        if state.get('session_id') != session_id:
            raise ValueError('session ID mismatch')
        return state
