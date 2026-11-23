"""Katana web crawler and endpoint discovery adapter."""
import json
from typing import List
from bughunter.adapters.base import BaseScannerAdapter, CapabilityManifest, AdapterMode, RawFinding


class KatanaAdapter(BaseScannerAdapter):
    def __init__(self):
        super().__init__(CapabilityManifest(
            name="katana",
            mode=AdapterMode.ACTIVE,
            timeout=120,
            rate_limit_cost=3,
            supported_targets=["url"],
            description="Next-generation crawling and spidering framework",
        ))

    def build_command(self, target: str, **kwargs) -> List[str]:
        depth = kwargs.get("depth", 2)
        cmd = ["katana", "-u", target, "-j", "-silent", "-depth", str(depth)]
        return cmd

    def parse_output(self, raw_output: str, target: str) -> List[RawFinding]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            endpoint = ""
            method = "GET"
            try:
                data = json.loads(line)
                req = data.get("request", {})
                endpoint = req.get("endpoint", "") or data.get("endpoint", "")
                method = req.get("method", "GET")
            except json.JSONDecodeError:
                endpoint = line

            if endpoint:
                findings.append(RawFinding(
                    tool="katana",
                    target=target,
                    endpoint=endpoint,
                    vuln_type="discovered_endpoint",
                    severity="INFO",
                    description=f"Crawled {method} {endpoint}",
                    raw_output=line,
                    evidence={"method": method, "endpoint": endpoint},
                ))
        return findings
