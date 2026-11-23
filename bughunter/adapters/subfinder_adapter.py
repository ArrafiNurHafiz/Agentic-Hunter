"""Subfinder passive subdomain discovery adapter."""
import json
from typing import List
from bughunter.adapters.base import BaseScannerAdapter, CapabilityManifest, AdapterMode, RawFinding


class SubfinderAdapter(BaseScannerAdapter):
    def __init__(self):
        super().__init__(CapabilityManifest(
            name="subfinder",
            mode=AdapterMode.PASSIVE,
            timeout=120,
            rate_limit_cost=0,
            supported_targets=["domain"],
            description="Passive subdomain discovery tool",
        ))

    def build_command(self, target: str, **kwargs) -> List[str]:
        # Strip scheme/port if passed as URL
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        cmd = ["subfinder", "-d", host, "-json", "-silent"]
        if "threads" in kwargs:
            cmd.extend(["-t", str(kwargs["threads"])])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> List[RawFinding]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            subdomain = ""
            try:
                data = json.loads(line)
                subdomain = data.get("host", "")
            except json.JSONDecodeError:
                subdomain = line

            if subdomain:
                findings.append(RawFinding(
                    tool="subfinder",
                    target=target,
                    endpoint=subdomain,
                    vuln_type="subdomain",
                    severity="INFO",
                    description=f"Discovered subdomain {subdomain}",
                    raw_output=line,
                ))
        return findings
