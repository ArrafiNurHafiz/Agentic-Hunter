import json
import socket
import sys

import pytest

from bughunter import __main__


@pytest.fixture
def scope_file(tmp_path):
    path = tmp_path / 'scope.yaml'
    path.write_text('''
version: "1.0"
authorized_by: AppSec
valid_until: 2099-01-01T00:00:00Z
in_scope:
  domains: [localhost]
  ips_and_cidrs: [10.0.0.0/24, "::1"]
  ports: [8000]
out_of_scope:
  ips: [10.0.0.254]
''')
    return path


def run_cli(monkeypatch, *args):
    monkeypatch.setattr(sys, 'argv', ['bughunter', 'attack', *args])
    __main__.main()


@pytest.mark.parametrize('target', ['localhost:8000', '10.0.0.4:8000', '[::1]:8000', '10.0.0.0/25'])
def test_local_scope_plan_uses_no_network(monkeypatch, capsys, scope_file, target):
    def unexpected_network(*args, **kwargs):
        pytest.fail('dry-run attempted network access')

    monkeypatch.setattr(socket, 'getaddrinfo', unexpected_network)
    monkeypatch.setattr(socket, 'socket', unexpected_network)
    run_cli(monkeypatch, target, '--scope', str(scope_file), '--dry-run', '--phase', '1-3')
    plan = json.loads(capsys.readouterr().out)
    assert plan['scope_declaration'] == 'validated'
    assert [phase['number'] for phase in plan['selected_phases']] == [1, 2, 3]


@pytest.mark.parametrize('target', ['localhost:9000', '10.0.0.254:8000', '10.0.0.0/24'])
def test_scope_rejects_denied_targets(monkeypatch, scope_file, target):
    with pytest.raises(SystemExit, match='outside the declared scope'):
        run_cli(monkeypatch, target, '--scope', str(scope_file), '--dry-run')


def test_expired_scope_is_rejected(monkeypatch, scope_file):
    scope_file.write_text(scope_file.read_text().replace('2099', '2000'))
    with pytest.raises(SystemExit, match='authorization has expired'):
        run_cli(monkeypatch, 'localhost:8000', '--scope', str(scope_file), '--dry-run')


def test_invalid_phase_is_rejected(monkeypatch):
    with pytest.raises(SystemExit, match='ascending range'):
        run_cli(monkeypatch, 'localhost:8000', '--dry-run', '--phase', '4-2')
