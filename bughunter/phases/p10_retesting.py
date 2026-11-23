"""Differential retesting and offline comparison of verified session snapshots."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from bughunter.core.session import SessionManager
from bughunter.memory.evidence import EvidenceStore, EvidenceError
from bughunter.memory.redaction import redact_obj


def compare_session_snapshots(
    baseline_session_id: str,
    current_session_id: str,
    manager: Optional[SessionManager] = None,
) -> Dict[str, Any]:
    """Compare two verified session snapshots offline.

    Guarantees:
    1. Both sessions are verified before comparison (state SHA-256 and evidence chain).
    2. Historical records, evidence, and reports in the baseline session are never overwritten.
    3. Never infers a vulnerability is fixed merely due to data variance or unobserved checks.
       A fix requires explicit, verified counter-evidence demonstrating safe remediation.
    """
    manager = manager or SessionManager()

    base_dir = manager.path(baseline_session_id)
    curr_dir = manager.path(current_session_id)

    # 1. Verify integrity of both snapshots
    base_state = manager.load(baseline_session_id)
    curr_state = manager.load(current_session_id)

    base_evidence = EvidenceStore(base_dir / 'evidence').read_verified()
    curr_evidence = EvidenceStore(curr_dir / 'evidence').read_verified()

    # Index current session evidence by finding_id
    curr_ev_by_finding: Dict[str, List[Dict[str, Any]]] = {}
    for r in curr_evidence:
        fid = r.get("finding_id")
        if fid:
            curr_ev_by_finding.setdefault(fid, []).append(r)

    # Extract baseline findings from state or evidence
    base_findings = base_state.get("findings", [])
    if not base_findings:
        seen_fids = set()
        for r in base_evidence:
            fid = r.get("finding_id")
            if fid and fid not in seen_fids:
                seen_fids.add(fid)
                base_findings.append({
                    "finding_id": fid,
                    "title": f"Finding {fid}",
                    "status": r.get("status", "CONFIRMED"),
                    "endpoint": r.get("url") or r.get("target") or "",
                })

    comparisons: List[Dict[str, Any]] = []
    fixed_list: List[Dict[str, Any]] = []
    still_present_list: List[Dict[str, Any]] = []
    regressions_list: List[Dict[str, Any]] = []
    inconclusive_list: List[Dict[str, Any]] = []

    for f in base_findings:
        fid = f.get("finding_id")
        title = f.get("title", fid)
        endpoint = f.get("endpoint", "")
        matching_curr = curr_ev_by_finding.get(fid, [])

        item: Dict[str, Any] = {
            "finding_id": fid,
            "title": title,
            "endpoint": endpoint,
            "baseline_status": f.get("status", "CONFIRMED"),
        }

        if not matching_curr:
            # Absence of test data is NOT evidence of a fix!
            item["status"] = "Inconclusive"
            item["rationale"] = "Finding unobserved or not re-evaluated in comparison session; absence of data is not evidence of fix."
            inconclusive_list.append(item)
        else:
            # Check for regression (500 server error or crash)
            has_regression = any(
                r.get("status") in ("REGRESSION", "CRASH")
                or (isinstance(r.get("response"), dict) and r.get("response", {}).get("status_code", 0) >= 500)
                for r in matching_curr
            )
            # Check for still present
            is_still_present = any(
                r.get("status") in ("CONFIRMED", "STILL_PRESENT", "OPEN")
                or (r.get("kind") == "validation" and "still" in (r.get("observation") or "").lower())
                for r in matching_curr
            )
            # Check for verified remediation
            is_verified_fixed = any(
                r.get("status") in ("RESOLVED", "FIXED", "PATCHED")
                for r in matching_curr
            )

            if has_regression:
                item["status"] = "Regression"
                item["rationale"] = "Target returned server error (500) or regression behavior on re-evaluation."
                regressions_list.append(item)
            elif is_still_present:
                item["status"] = "Still Present"
                item["rationale"] = "Vulnerability reproduced or confirmed still present in comparison session."
                still_present_list.append(item)
            elif is_verified_fixed:
                item["status"] = "Fixed"
                item["rationale"] = "Verified counter-evidence confirms the vulnerability was safely remediated and endpoint remains functional."
                fixed_list.append(item)
            else:
                # Data differed, but no verified proof of remediation!
                item["status"] = "Inconclusive"
                item["rationale"] = "Response data differs from baseline, but data variance alone does not constitute proof of remediation."
                inconclusive_list.append(item)

        comparisons.append(item)

    diff_report = redact_obj({
        "comparison_type": "differential_snapshot_comparison",
        "baseline_session_id": baseline_session_id,
        "current_session_id": current_session_id,
        "compared_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_baseline_findings": len(base_findings),
            "fixed": len(fixed_list),
            "still_present": len(still_present_list),
            "regressions": len(regressions_list),
            "inconclusive": len(inconclusive_list),
        },
        "comparisons": comparisons,
    })

    # Save differential reports in the current session (never overwriting baseline)
    reports_dir = curr_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    json_path = reports_dir / "retest_diff.json"
    manager._atomic(json_path, (json.dumps(diff_report, indent=2) + "\n").encode("utf-8"))

    md_content = _render_retest_markdown(diff_report)
    md_path = reports_dir / "RETEST_REPORT.md"
    manager._atomic(md_path, md_content.encode("utf-8"))

    return diff_report


def retest_session(session_id: str, manager: Optional[SessionManager] = None) -> Dict[str, Any]:
    """Offline differential retest analysis for a single session."""
    manager = manager or SessionManager()
    session_dir = manager.path(session_id)
    state = manager.load(session_id)
    evidence = EvidenceStore(session_dir / "evidence").read_verified()

    findings = state.get("findings", [])
    ev_by_fid: Dict[str, List[Dict[str, Any]]] = {}
    for r in evidence:
        fid = r.get("finding_id")
        if fid:
            ev_by_fid.setdefault(fid, []).append(r)

    fixed = []
    still_present = []
    regressions = []
    inconclusive = []

    for f in findings:
        fid = f.get("finding_id")
        evs = ev_by_fid.get(fid, [])
        item = {
            "finding_id": fid,
            "title": f.get("title", fid),
        }
        has_reg = any(r.get("status") in ("REGRESSION", "CRASH") for r in evs)
        has_fixed = any(r.get("status") in ("RESOLVED", "FIXED", "PATCHED") for r in evs)
        has_still = any(r.get("status") in ("CONFIRMED", "STILL_PRESENT") for r in evs)

        if has_reg:
            item["status"] = "Regression"
            regressions.append(item)
        elif has_fixed:
            item["status"] = "Fixed"
            fixed.append(item)
        elif has_still or f.get("status") == "CONFIRMED":
            item["status"] = "Still Present"
            still_present.append(item)
        else:
            item["status"] = "Inconclusive"
            item["rationale"] = "Insufficient counter-evidence to determine remediation status."
            inconclusive.append(item)

    result = redact_obj({
        "session_id": session_id,
        "target": state.get("target"),
        "retested_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "fixed": len(fixed),
            "still_present": len(still_present),
            "regressions": len(regressions),
            "inconclusive": len(inconclusive),
        },
        "fixed": fixed,
        "still_present": still_present,
        "regressions": regressions,
        "inconclusive": inconclusive,
    })
    result["session_id"] = session_id

    reports_dir = session_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    manager._atomic(reports_dir / "retest_report.json", (json.dumps(result, indent=2) + "\n").encode("utf-8"))
    return result


def _render_retest_markdown(diff: Dict[str, Any]) -> str:
    lines = [
        "# Differential Retest Report",
        "",
        f"- **Baseline Session:** `{diff.get('baseline_session_id')}`",
        f"- **Comparison Session:** `{diff.get('current_session_id')}`",
        f"- **Compared At:** {diff.get('compared_at')}",
        "",
        "## Summary",
        f"- **Fixed:** {diff['summary']['fixed']}",
        f"- **Still Present:** {diff['summary']['still_present']}",
        f"- **Regressions:** {diff['summary']['regressions']}",
        f"- **Inconclusive:** {diff['summary']['inconclusive']}",
        "",
        "## Comparisons",
        "",
    ]
    for c in diff.get("comparisons", []):
        lines.append(f"### [{c['status']}] {c.get('title', c['finding_id'])}")
        lines.append(f"- **Finding ID:** `{c['finding_id']}`")
        if c.get("endpoint"):
            lines.append(f"- **Endpoint:** `{c['endpoint']}`")
        lines.append(f"- **Rationale:** {c.get('rationale', 'N/A')}")
        lines.append("")

    lines.append("Note: Fixes are asserted only when supported by verified counter-evidence; data variance alone is not considered proof of fix.")
    return "\n".join(lines) + "\n"
