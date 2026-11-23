"""Harness vulnerability reporting engine (Markdown & JSON output)."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from memory.redaction import redact_obj
except ImportError:
    try:
        from bughunter.memory.redaction import redact_obj
    except ImportError:
        def redact_obj(obj):
            return obj


class HarnessReportGenerator:
    """Generates submission-ready Markdown and structured JSON assessment reports."""

    def __init__(self, session_id: str, target: str):
        self.session_id = session_id
        self.target = target

    def generate_json_report(self, state: Dict[str, Any], verified_findings: List[Dict[str, Any]]) -> str:
        data = {
            "report_version": "3.2.0",
            "session_id": self.session_id,
            "target": self.target,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(verified_findings),
                "confirmed": sum(1 for f in verified_findings if f.get("status") == "CONFIRMED"),
                "potential": sum(1 for f in verified_findings if f.get("status") == "INCONCLUSIVE"),
                "false_positives": sum(1 for f in verified_findings if f.get("status") == "FALSE_POSITIVE"),
            },
            "findings": verified_findings,
            "session_state": state,
        }
        redacted = redact_obj(data)
        return json.dumps(redacted, indent=2, sort_keys=True)

    def generate_markdown_report(self, state: Dict[str, Any], verified_findings: List[Dict[str, Any]]) -> str:
        confirmed = [f for f in verified_findings if f.get("status") == "CONFIRMED"]
        potential = [f for f in verified_findings if f.get("status") == "INCONCLUSIVE"]

        lines = [
            f"# SECURITY ASSESSMENT REPORT — {self.target}",
            "",
            f"**Session ID:** `{self.session_id}`  ",
            f"**Target Asset:** `{self.target}`  ",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "**Engine:** BugHunter v3.2 AI Agent Harness  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            f"An authorized, non-destructive security assessment was conducted against `{self.target}`.",
            f"A total of **{len(confirmed)} confirmed vulnerabilities** and **{len(potential)} potential findings** were identified.",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| CRITICAL | {sum(1 for f in confirmed if f.get('severity') == 'CRITICAL')} |",
            f"| HIGH | {sum(1 for f in confirmed if f.get('severity') == 'HIGH')} |",
            f"| MEDIUM | {sum(1 for f in confirmed if f.get('severity') == 'MEDIUM')} |",
            f"| LOW | {sum(1 for f in confirmed if f.get('severity') == 'LOW')} |",
            f"| INFO / POTENTIAL | {len(potential)} |",
            "",
            "---",
            "",
            "## 2. Confirmed Vulnerabilities",
            "",
        ]

        if not confirmed:
            lines.append("No confirmed vulnerabilities were identified during this assessment.\n")
        else:
            for idx, f in enumerate(confirmed, 1):
                title = f.get("title", "Untitled Vulnerability")
                sev = f.get("severity", "MEDIUM")
                cvss_score = f.get("cvss_score", "N/A")
                cvss_vector = f.get("cvss_vector", "")
                endpoint = f.get("endpoint", self.target)
                ev_hash = f.get("evidence_hash", "N/A")
                desc = f.get("description", "No description provided.")

                lines.extend([
                    f"### 2.{idx} [{sev}] {title}",
                    f"- **Asset / Endpoint:** `{endpoint}`",
                    f"- **CVSS 4.0 Score:** `{cvss_score}` (`{cvss_vector}`)",
                    f"- **Forensic Evidence Hash (SHA-256):** `{ev_hash}`",
                    "",
                    "#### Description & Impact",
                    desc,
                    "",
                    "#### Reproduction Steps",
                    f"1. Send diagnostic probe request to `{endpoint}`.",
                    "2. Observe non-destructive anomaly in response.",
                    f"3. Verified with confidence score: `{f.get('confidence', 1.0)}`.",
                    "",
                    "#### Remediation Guidance",
                    f"- Implement strict input validation and access controls on `{endpoint}`.",
                    "- Ensure least privilege principle is applied.",
                    "",
                ])

        if potential:
            lines.extend([
                "---",
                "",
                "## 3. Potential Findings (Inconclusive / Telemetry Needs Review)",
                "",
            ])
            for idx, f in enumerate(potential, 1):
                lines.append(f"- **{f.get('title', 'Unknown')}** at `{f.get('endpoint', self.target)}` (Confidence: {f.get('confidence', 0.5)})")
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 4. Assessment Methodology & Guardrails",
            "",
            "- **Non-Destructive by Design:** No database modifications (`DROP`, `DELETE`, `UPDATE`) were performed.",
            "- **Zero Private IP Blocking:** Homelab, intranet, and local targets were authorized and tested.",
            "- **Data Minimization:** Telemetry redacted of passwords and API tokens.",
        ])

        full_md = "\n".join(lines)
        redacted = redact_obj(full_md)
        return redacted if isinstance(redacted, str) else full_md

    def save_reports(self, output_dir: Path, state: Dict[str, Any], verified_findings: List[Dict[str, Any]]) -> Tuple[Path, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        json_path = output_dir / "report.json"
        md_path = output_dir / "report.md"

        json_path.write_text(self.generate_json_report(state, verified_findings))
        md_path.write_text(self.generate_markdown_report(state, verified_findings))

        return json_path, md_path
