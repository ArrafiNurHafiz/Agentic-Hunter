import pytest
from bughunter.core.scope import ContinuousScope, ScopeDecision
from bughunter.core.policy_engine import PolicyEngine


def test_scope_local_and_exclusions():
    scope = ContinuousScope({'valid_until': '2099-01-01T00:00:00Z',
        'in_scope': {'domains': ['localhost', '*.corp.local'], 'ips_and_cidrs': ['192.168.1.0/24'], 'ports': [8000]},
        'out_of_scope': {'ips': ['192.168.1.254']}})
    assert scope.validate_action('http://localhost:8000/') == ScopeDecision.ALLOW
    assert scope.validate_action('http://192.168.1.1:8000/') == ScopeDecision.ALLOW
    assert scope.validate_action('http://192.168.1.254:8000/') == ScopeDecision.BLOCK_OUT_OF_SCOPE
    assert scope.validate_action('http://localhost:8001/') == ScopeDecision.BLOCK_OUT_OF_SCOPE
    assert scope.validate_action('http://localhost:8000/', 'DELETE') == ScopeDecision.BLOCK_UNSAFE_METHOD


def test_circuit_breaker():
    policy = PolicyEngine(error_threshold=2)
    policy.record(500)
    policy.record(503)
    with pytest.raises(RuntimeError, match='circuit'):
        with policy.request():
            pass


def test_redirect_denied_before_request(monkeypatch):
    from urllib.request import Request
    from urllib.error import URLError
    from bughunter.core.scope import scoped_urlopen
    from bughunter.tools import safe_http
    calls = []
    class Response:
        status = 302
        headers = {'Location': 'http://outside.test/'}
        def close(self):
            pass
    def hop(request, timeout):
        calls.append(request.full_url)
        return Response()
    monkeypatch.setattr(safe_http, '_one_hop', hop)
    scope = ContinuousScope({'valid_until': '2099-01-01T00:00:00Z', 'in_scope': {'domains': ['localhost']}})
    with pytest.raises(URLError, match='scope denied'):
        scoped_urlopen(Request('http://localhost/'), scope, PolicyEngine())
    assert calls == ['http://localhost/']


def test_expired_scope():
    scope = ContinuousScope({'valid_until': '2000-01-01T00:00:00Z', 'in_scope': {'domains': ['localhost']}})
    assert scope.validate_action('http://localhost/') == ScopeDecision.BLOCK_EXPIRED


@pytest.mark.parametrize('url', [
    'ftp://localhost:8000/',
    'http://localhost:0/',
    'http://user:password@localhost:8000/',
])
def test_scope_rejects_ambiguous_or_non_http_urls(url):
    scope = ContinuousScope({'valid_until': '2099-01-01T00:00:00Z',
                             'in_scope': {'domains': ['localhost'], 'ports': [8000]}})
    assert scope.validate_action(url) == ScopeDecision.BLOCK_OUT_OF_SCOPE


def test_subprocess_timeout():
    import subprocess
    import sys
    from bughunter.core.executor import run_command
    with pytest.raises(subprocess.TimeoutExpired):
        run_command([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=0.05)


def test_http_errors_trip_breaker(monkeypatch):
    from urllib.error import HTTPError
    from urllib.request import Request
    from bughunter.core.scope import scoped_urlopen
    from bughunter.tools import safe_http
    def hop(request, timeout):
        raise HTTPError(request.full_url, 503, 'unavailable', {}, None)
    monkeypatch.setattr(safe_http, '_one_hop', hop)
    scope = ContinuousScope({'valid_until': '2099-01-01T00:00:00Z', 'in_scope': {'domains': ['localhost']}})
    policy = PolicyEngine(error_threshold=1)
    assert scoped_urlopen(Request('http://localhost/'), scope, policy).status == 503
    with pytest.raises(RuntimeError, match='circuit'):
        scoped_urlopen(Request('http://localhost/'), scope, policy)
