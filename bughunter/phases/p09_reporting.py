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

    ev_by_finding: dict[str, list[dict]] = {}
    for r in records:
        fid = r.get('finding_id')
        if fid:
            ev_by_finding.setdefault(fid, []).append(r)

    raw_findings = state.get('findings', [])
    findings_list = []
    if raw_findings:
        for f in raw_findings:
            f_out = dict(f)
            fid = f.get('finding_id')
            supporting_ev = ev_by_finding.get(fid, []) if fid else []
            has_confirmed_evidence = any(
                r.get('status') in ('CONFIRMED', 'VALIDATED') or r.get('kind') in ('validation', 'finding')
                for r in supporting_ev
            )
            if supporting_ev and has_confirmed_evidence:
                f_out['status'] = f.get('status', 'CONFIRMED')
                f_out['evidence_digests'] = [r['digest'] for r in supporting_ev if 'digest' in r]
                f_out['validation_note'] = 'Confirmed by verified evidence records'
            else:
                f_out['status'] = 'INCONCLUSIVE'
                f_out['evidence_digests'] = [r['digest'] for r in supporting_ev if 'digest' in r]
                f_out['validation_note'] = 'Verdict unverified: no matching verified evidence in provenance chain.'
            findings_list.append(f_out)
    else:
        for fid, evs in ev_by_finding.items():
            has_confirmed = any(r.get('status') in ('CONFIRMED', 'VALIDATED') for r in evs)
            findings_list.append({
                'finding_id': fid,
                'status': 'CONFIRMED' if has_confirmed else 'INCONCLUSIVE',
                'evidence_digests': [r['digest'] for r in evs if 'digest' in r],
                'validation_note': 'Derived from verified evidence' if has_confirmed else 'Verdict unverified',
            })

    report = redact_obj({
        'assessment_id': session_id,
        'target': state['target'],
        'phases': state['phases'],
        'evidence': [{key: record[key] for key in evidence_fields if key in record}
                     for record in records],
        'findings': findings_list,
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

    findings = report.get('findings', [])
    confirmed = [f for f in findings if f.get('status') == 'CONFIRMED']
    unverified = [f for f in findings if f.get('status') != 'CONFIRMED']

    if confirmed:
        lines.extend(['', '## Confirmed Findings (Supported by Verified Evidence)', ''])
        for f in confirmed:
            title = f.get('title', f.get('finding_id', 'Untitled Finding'))
            lines.append(f"- **[{f.get('severity', 'CONFIRMED')}] {title}** (`{f.get('finding_id', 'N/A')}`)")
            if f.get('endpoint'):
                lines.append(f"  - Endpoint: `{f['endpoint']}`")
            if f.get('description'):
                lines.append(f"  - Description: {f['description']}")
            if f.get('evidence_digests'):
                lines.append(f"  - Verified Evidence Digests: {', '.join(f['evidence_digests'])}")

    if unverified:
        lines.extend(['', '## Inconclusive / Unverified Findings', ''])
        for f in unverified:
            title = f.get('title', f.get('finding_id', 'Untitled Finding'))
            lines.append(f"- **[INCONCLUSIVE] {title}** (`{f.get('finding_id', 'N/A')}`)")
            lines.append(f"  - Note: {f.get('validation_note', 'No verified evidence')}")

    lines.extend(['', 'This export summarizes saved records and assigns no finding verdicts without verified evidence.'])
    return '\n'.join(lines) + '\n'
