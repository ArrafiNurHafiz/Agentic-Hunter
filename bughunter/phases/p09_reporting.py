"""Offline exports of assessment session state and verified evidence metadata."""
import json

from bughunter.core.session import SessionManager
from bughunter.memory.evidence import EvidenceStore
from bughunter.memory.redaction import redact_obj


def write_session_report(session_id, output_format, manager=None):
    manager = manager or SessionManager()
    directory = manager.path(session_id)
    state = manager.load(session_id)
    records = EvidenceStore(directory / 'evidence').read_verified()
    evidence_fields = ('evidence_id', 'finding_id', 'parent_id', 'ts', 'kind', 'digest')
    report = redact_obj({
        'assessment_id': session_id,
        'target': state['target'],
        'phases': state['phases'],
        'evidence': [{key: record[key] for key in evidence_fields if key in record}
                     for record in records],
    })
    if output_format == 'json':
        suffix = 'json'
        rendered = json.dumps(report, indent=2) + '\n'
    elif output_format == 'markdown':
        suffix = 'md'
        rendered = _markdown(report)
    else:
        raise ValueError('expected markdown or json report format')
    output_dir = directory / 'reports'
    output_dir.mkdir(exist_ok=True)
    output = output_dir / f'ASSESSMENT_REPORT.{suffix}'
    manager._atomic(output, rendered.encode('utf-8'))
    return output


def _markdown(report):
    lines = ['# Assessment session report', '',
             '    Assessment: ' + json.dumps(report['assessment_id']),
             '    Target: ' + json.dumps(report['target']), '',
             '## Phase status', '']
    for phase in report['phases']:
        lines.append('    ' + json.dumps(phase, ensure_ascii=True))
    lines.extend(['', '## Evidence provenance', ''])
    if report['evidence']:
        for record in report['evidence']:
            lines.append('    ' + json.dumps(record, ensure_ascii=True))
    else:
        lines.append('No evidence was recorded for this session.')
    lines.extend(['', 'This export summarizes saved records and assigns no finding verdicts.'])
    return '\n'.join(lines) + '\n'
