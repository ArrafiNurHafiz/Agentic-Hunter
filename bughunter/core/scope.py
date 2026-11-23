"""Authorization decisions for assessment actions, including local targets."""
from datetime import datetime, timedelta, timezone
from enum import Enum
import ipaddress
from urllib.parse import urlsplit

from bughunter.tools.scope_checker import ScopeChecker


class ScopeDecision(str, Enum):
    ALLOW = 'allow'
    BLOCK_EXPIRED = 'block_expired'
    BLOCK_OUT_OF_SCOPE = 'block_out_of_scope'
    BLOCK_UNSAFE_METHOD = 'block_unsafe_method'


class ContinuousScope:
    def __init__(self, spec):
        self.spec = spec
        expiry = spec.get('valid_until')
        if not isinstance(expiry, str):
            raise ValueError('valid_until is required')
        self.expiry = datetime.fromisoformat(expiry.replace('Z', '+00:00'))
        if self.expiry.tzinfo is None:
            raise ValueError('valid_until must include timezone')
        allowed = spec.get('in_scope', {})
        denied = spec.get('out_of_scope', {})
        self.checker = ScopeChecker(allowed.get('domains', []) + allowed.get('ips_and_cidrs', []),
                                    denied.get('domains', []) + denied.get('ips', []))
        self.ports = set(allowed.get('ports', []))

    @classmethod
    def default_for_target(cls, target: str, valid_hours: int = 24) -> 'ContinuousScope':
        clean_target = target.strip()
        if not clean_target.startswith(('http://', 'https://')):
            url_to_parse = 'http://' + clean_target
        else:
            url_to_parse = clean_target
        parsed = urlsplit(url_to_parse)
        host = parsed.hostname or clean_target
        port = parsed.port
        ports = [port] if port else []

        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        in_scope = {
            'domains': [host] if not is_ip else [],
            'ips_and_cidrs': [host] if is_ip else [],
            'ports': ports,
        }
        valid_until = (datetime.now(timezone.utc) + timedelta(hours=valid_hours)).isoformat()
        return cls({
            'valid_until': valid_until,
            'in_scope': in_scope,
            'out_of_scope': {},
        })

    def is_expired(self):
        return datetime.now(timezone.utc) >= self.expiry

    def validate_action(self, url, method='GET'):
        if self.is_expired():
            return ScopeDecision.BLOCK_EXPIRED
        if method.upper() not in ('GET', 'HEAD', 'OPTIONS', 'POST'):
            return ScopeDecision.BLOCK_UNSAFE_METHOD
        try:
            parsed = urlsplit(url)
            port = parsed.port or {'http': 80, 'https': 443}.get(parsed.scheme)
            if not port or (self.ports and port not in self.ports) or not self.checker.is_in_scope(url):
                return ScopeDecision.BLOCK_OUT_OF_SCOPE
        except ValueError:
            return ScopeDecision.BLOCK_OUT_OF_SCOPE
        return ScopeDecision.ALLOW


def scoped_urlopen(request, scope, policy, timeout=10, max_redirects=5, audit=None):
    """Validate every redirect hop before issuing it; never auto-follow redirects."""
    from urllib.error import HTTPError, URLError
    from urllib.parse import urljoin
    from urllib.request import Request
    from bughunter.tools.safe_http import _one_hop

    current = request
    for hop in range(max_redirects + 1):
        decision = scope.validate_action(current.full_url, current.get_method())
        if decision != ScopeDecision.ALLOW:
            if audit:
                audit(current.full_url, current.get_method(), decision.value)
            raise URLError(f'scope denied: {decision.value}')
        with policy.request():
            try:
                response = _one_hop(current, timeout)
            except HTTPError as error:
                response = error
            policy.record(response.status)
        if audit:
            audit(current.full_url, current.get_method(), decision.value)
        if response.status not in (301, 302, 303, 307, 308) or not response.headers.get('Location'):
            return response
        if hop == max_redirects:
            response.close()
            raise URLError('too many redirects')
        next_url = urljoin(current.full_url, response.headers['Location'])
        preserve = response.status in (307, 308)
        # Never forward credentials to a different origin.
        old, new = urlsplit(current.full_url), urlsplit(next_url)
        headers = dict(current.header_items())
        if (old.scheme, old.netloc) != (new.scheme, new.netloc):
            headers = {k: v for k, v in headers.items() if k.lower() not in ('authorization', 'cookie', 'proxy-authorization')}
        response.close()
        current = Request(next_url, data=current.data if preserve else None,
                          headers=headers, method=current.get_method() if preserve else 'GET')
    raise URLError('too many redirects')
