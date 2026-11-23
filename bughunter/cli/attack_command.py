"""Assessment command registration."""
import json
import re

from bughunter.core.session import SessionManager
from bughunter.core.state_machine import new_phases


def register(subparsers):
    parser = subparsers.add_parser('attack', help='Validate assessment plans and inspect sessions')
    parser.add_argument('target', help='Target, or resume/status/retest followed by a session ID')
    parser.add_argument('session_id', nargs='?')
    parser.add_argument('--scope', help='Authorization scope YAML')
    parser.add_argument('--dry-run', action='store_true', help='Validate target and scope without network access')
    parser.add_argument('--profile', choices=('passive', 'active'), default='active')
    parser.add_argument('--phase', help='Phase number or inclusive range, e.g. 1-3')
    return parser


def run(args):
    try:
        if args.target == 'status':
            if not args.session_id or args.dry_run or args.scope or args.phase:
                raise ValueError('usage: bughunter attack status <session_id>')
            result = SessionManager().load(args.session_id)
        elif args.target == 'retest':
            if not args.session_id:
                raise ValueError('usage: bughunter attack retest <session_id>')
            manager = SessionManager()
            from bughunter.phases.p10_retesting import retest_session
            result = retest_session(args.session_id, manager=manager)
        elif args.target == 'resume' or not args.dry_run:
            raise ValueError('assessment execution is unavailable; use --dry-run to validate a plan')
        elif args.session_id:
            raise ValueError('unexpected second argument after target')
        else:
            result = _plan(args)
    except (ValueError, OSError) as error:
        raise SystemExit(f'attack: {error}') from None
    print(json.dumps(result, indent=2))


def _plan(args):
    from bughunter.phases.p01_scope import check_target, load_scope

    phases = new_phases()
    first, last = 1, len(phases)
    if args.phase is not None:
        match = re.fullmatch(r'([0-9]{1,2})(?:-([0-9]{1,2}))?', args.phase)
        if not match:
            raise ValueError('--phase must be a phase number or range, e.g. 1-3')
        first = int(match[1])
        last = int(match[2] or match[1])
        if not 1 <= first <= last <= len(phases):
            raise ValueError('--phase must select an ascending range within 1-10')

    scope = load_scope(args.scope) if args.scope is not None else None
    return {
        'mode': 'dry-run',
        'target': check_target(args.target, scope),
        'profile': args.profile,
        'scope_declaration': 'validated' if scope else 'not provided',
        'selected_phases': [{'number': phase.number, 'name': phase.name}
                            for phase in phases if first <= phase.number <= last],
    }
