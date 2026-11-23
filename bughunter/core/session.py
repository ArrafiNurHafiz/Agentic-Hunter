"""Persistent assessment sessions with atomic snapshots and integrity checks.

Trust boundary: Session state and artifact integrity checks use local SHA-256 digests.
This provides detection of corruption or accidental/uncoordinated modifications (tamper detection),
but does not protect against a privileged adversary with write access who can overwrite both
data and hash files simultaneously.
"""
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
    """Manages assessment sessions, atomic state persistence, and artifact integrity.

    Trust boundary: Session state and artifact integrity checks use local SHA-256 digests.
    This provides detection of corruption or accidental/uncoordinated modifications (tamper detection),
    but does not protect against a privileged adversary with write access who can overwrite both
    data and hash files simultaneously.
    """

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
            (directory / name).mkdir(exist_ok=True)
        state = {
            'session_id': session_id,
            'target': target,
            'phases': [{'number': p.number, 'name': p.name, 'status': p.status.value} for p in new_phases()],
        }
        self.save(state)
        return state

    @staticmethod
    def _atomic(path, data):
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def save(self, state):
        directory = self.path(state['session_id'])
        directory.mkdir(parents=True, exist_ok=True)
        data = (json.dumps(state, indent=2, sort_keys=True) + '\n').encode('utf-8')
        digest = (hashlib.sha256(data).hexdigest() + '\n').encode('utf-8')

        state_file = directory / 'state.json'
        hash_file = directory / 'state.sha256'

        prev_state = state_file.read_bytes() if state_file.is_file() else None
        prev_hash = hash_file.read_bytes() if hash_file.is_file() else None

        try:
            self._atomic(state_file, data)
            self._atomic(hash_file, digest)
        except Exception:
            if prev_state is not None and prev_hash is not None:
                try:
                    self._atomic(state_file, prev_state)
                    self._atomic(hash_file, prev_hash)
                except Exception:
                    pass
            raise

    def load(self, session_id):
        directory = self.path(session_id)
        state_file = directory / 'state.json'
        hash_file = directory / 'state.sha256'

        if not state_file.is_file():
            raise FileNotFoundError(f'session state file not found: {state_file}')
        if not hash_file.is_file():
            raise ValueError('session state integrity check failed: missing hash anchor')

        data = state_file.read_bytes()
        expected = hash_file.read_text().strip()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError('session state integrity check failed')

        try:
            state = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError(f'session state integrity check failed: corrupt json ({exc})') from exc

        if not isinstance(state, dict) or state.get('session_id') != session_id:
            raise ValueError('session ID mismatch')
        return state

    # ── Session Artifacts Integrity ──────────────────────────────────────────

    def _validate_artifact_name(self, name: str) -> str:
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name.startswith('.') or '..' in name or name.endswith('.sha256') or name.endswith('.tmp'):
            raise ValueError(f'invalid artifact name: {name}')
        return name

    def save_artifact(self, session_id: str, name: str, data: bytes | str) -> Path:
        """Save a named session artifact with atomic write and SHA-256 integrity hash."""
        clean_name = self._validate_artifact_name(name)
        directory = self.path(session_id) / 'artifacts'
        directory.mkdir(parents=True, exist_ok=True)

        data_bytes = data.encode('utf-8') if isinstance(data, str) else data
        digest_bytes = (hashlib.sha256(data_bytes).hexdigest() + '\n').encode('utf-8')

        art_file = directory / clean_name
        hash_file = directory / f'{clean_name}.sha256'

        prev_data = art_file.read_bytes() if art_file.is_file() else None
        prev_hash = hash_file.read_bytes() if hash_file.is_file() else None

        try:
            self._atomic(art_file, data_bytes)
            self._atomic(hash_file, digest_bytes)
        except Exception:
            if prev_data is not None and prev_hash is not None:
                try:
                    self._atomic(art_file, prev_data)
                    self._atomic(hash_file, prev_hash)
                except Exception:
                    pass
            raise
        return art_file

    def verify_artifact(self, session_id: str, name: str) -> bool:
        """Verify whether an artifact exists and matches its SHA-256 hash anchor."""
        clean_name = self._validate_artifact_name(name)
        directory = self.path(session_id) / 'artifacts'
        art_file = directory / clean_name
        hash_file = directory / f'{clean_name}.sha256'

        if not art_file.is_file() or not hash_file.is_file():
            return False

        try:
            data = art_file.read_bytes()
            expected = hash_file.read_text().strip()
            return hashlib.sha256(data).hexdigest() == expected
        except OSError:
            return False

    def load_artifact(self, session_id: str, name: str, as_text: bool = False) -> bytes | str:
        """Load and verify an artifact. Rejects modified or missing hash anchor artifacts."""
        clean_name = self._validate_artifact_name(name)
        directory = self.path(session_id) / 'artifacts'
        art_file = directory / clean_name
        hash_file = directory / f'{clean_name}.sha256'

        if not art_file.is_file():
            raise FileNotFoundError(f'artifact file not found: {name}')
        if not hash_file.is_file():
            raise ValueError(f'artifact integrity check failed for {name}: missing hash anchor')

        data = art_file.read_bytes()
        expected = hash_file.read_text().strip()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f'artifact integrity check failed for {name}')

        return data.decode('utf-8') if as_text else data

    def list_artifacts(self, session_id: str) -> list[str]:
        """List verified artifact filenames in the session (excluding hashes and temp files)."""
        directory = self.path(session_id) / 'artifacts'
        if not directory.is_dir():
            return []
        items = []
        for path in sorted(directory.iterdir()):
            if path.is_file() and not path.name.endswith('.sha256') and not path.name.endswith('.tmp'):
                items.append(path.name)
        return items
