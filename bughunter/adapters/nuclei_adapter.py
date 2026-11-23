"""Nuclei vulnerability scanner adapter."""
import json
from typing import List
from bughunter.adapters.base import BaseScannerAdapter, CapabilityManifest, AdapterMode, RawFinding


class NucleiAdapter(BaseScannerAdapter):
    def __init__(self):
        super().__init__(CapabilityManifest(
            name="nuclei",
            mode=AdapterMode.ACTIVE,
            timeout=300,
            rate_limit_cost=5,
            supported_targets=["domain", "ip", "url"],
            description="Fast and customizable vulnerability scanner based on simple YAML DSL",
        ))

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
        tags = kwargs.get("tags")
        if tags:
            cmd.extend(["-tags", tags if isinstance(tags, str) else ",".join(tags)])
        severity = kwargs.get("severity")
        if severity:
            cmd.extend(["-severity", severity if isinstance(severity, str) else ",".join(severity)])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> List[RawFinding]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                template_id = data.get("template-id", "nuclei_finding")
                info = data.get("info", {})
                name = info.get("name", template_id)
                severity = info.get("severity", "info").upper()
                matched_at = data.get("matched-at", target)
                cve_id = (info.get("classification") or {}).get("cve-id")

                findings.append(RawFinding(
                    tool="nuclei",
                    target=target,
                    endpoint=matched_at,
                    vuln_type=template_id,
                    severity=severity,
                    description=f"{name} ({template_id})" + (f" [{cve_id}]" if cve_id else ""),
                    raw_output=line,
                    evidence={
                        "template_id": template_id,
                        "name": name,
                        "type": data.get("type"),
                        "matched_at": matched_at,
                        "curl_command": data.get("curl-command"),
                        "extracted_results": data.get("extracted-results"),
                    },
                ))
            except json.JSONDecodeError:
                continue
        return findings
