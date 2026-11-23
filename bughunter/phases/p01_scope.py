"""Offline validation of an operator's scope declaration."""
import ipaddress
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from bughunter.core.scope import ContinuousScope, ScopeDecision
from bughunter.tools.scope_checker import _normalize_and_parse, _parse_pattern


def load_scope(path):
    try:
        spec = yaml.safe_load(Path(path).read_text(encoding='utf-8'))
    except yaml.YAMLError as error:
        raise ValueError('invalid YAML scope document') from error
    if not isinstance(spec, dict):
        raise ValueError('scope document must be a mapping')
    if str(spec.get('version')) != '1.0':
        raise ValueError('scope version must be 1.0')
    if not isinstance(spec.get('authorized_by'), str) or not spec['authorized_by'].strip():
        raise ValueError('authorized_by is required')
    expiry = spec.get('valid_until')
    if isinstance(expiry, datetime):
        spec['valid_until'] = expiry.isoformat()
    for section, fields in (('in_scope', ('domains', 'ips_and_cidrs')),
                            ('out_of_scope', ('domains', 'ips'))):
        rules = spec.get(section, {})
        if not isinstance(rules, dict):
            raise ValueError(f'{section} must be a mapping')
        for field in fields:
            items = rules.get(field, [])
            if not isinstance(items, list) or any(
                not isinstance(item, str) or not _parse_pattern(item) for item in items
            ):
                raise ValueError(f'{section}.{field} must be a list of valid scope patterns')
    allowed = spec.get('in_scope', {})
    if not (allowed.get('domains') or allowed.get('ips_and_cidrs')):
        raise ValueError('in_scope must include at least one target')
    ports = allowed.get('ports', [])
    if not isinstance(ports, list) or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
        raise ValueError('in_scope.ports must be a list of valid port numbers')
    scope = ContinuousScope(spec)
    if scope.is_expired():
        raise ValueError('scope authorization has expired')
    return scope


def check_target(target, scope=None):
    """Check a URL, host, or CIDR as written, without DNS or connections."""
    if '/' in target:
        try:
            network = ipaddress.ip_network(target, strict=True)
        except ValueError:
            network = None
        if network is not None:
            if scope is not None:
                allowed = scope.spec['in_scope']
                denied = scope.spec.get('out_of_scope', {})
                includes = _networks(allowed.get('ips_and_cidrs', []) + allowed.get('domains', []))
                excludes = _networks(denied.get('ips', []) + denied.get('domains', []))
                if not any(network.subnet_of(rule) for rule in includes if rule.version == network.version) or any(
                    network.overlaps(rule) for rule in excludes
                ):
                    raise ValueError('target CIDR is outside the declared scope')
            return str(network)
    if re.fullmatch(r'[0-9a-fA-F:]+', target) and ':' in target and target.count(':') > 1:
        target = f'[{target}]'
    explicit_scheme = '://' in target
    url = target if explicit_scheme else f'https://{target}'
    if not _normalize_and_parse(url):
        raise ValueError('invalid assessment target')
    parsed = urlsplit(url)
    if parsed.username is not None or parsed.password is not None or parsed.port == 0:
        raise ValueError('invalid assessment target authority')
    if scope is not None:
        candidates = [url] if explicit_scheme else [url, f'http://{target}']
        if not any(scope.validate_action(candidate) == ScopeDecision.ALLOW for candidate in candidates):
            raise ValueError('target is outside the declared scope')
    return target


def _networks(patterns):
    for pattern in patterns:
        rule = _parse_pattern(pattern)
        if rule['kind'] == 'ip':
            yield rule['network']
