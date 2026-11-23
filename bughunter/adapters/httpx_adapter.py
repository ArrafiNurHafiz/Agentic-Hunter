"""Httpx HTTP probing and technology identification adapter."""
import json
from typing import List
from bughunter.adapters.base import BaseScannerAdapter, CapabilityManifest, AdapterMode, RawFinding


class HttpxAdapter(BaseScannerAdapter):
    def __init__(self):
        super().__init__(CapabilityManifest(
            name="httpx",
            mode=AdapterMode.ACTIVE,
            timeout=90,
            rate_limit_cost=2,
            supported_targets=["domain", "ip", "url"],
            description="HTTP service probe, tech stack detection, and title grabber",
        ))

    def build_command(self, target: str, **kwargs) -> List[str]:
        cmd = ["httpx", "-u", target, "-json", "-silent", "-status-code", "-tech-detect", "-title"]
        if "ports" in kwargs and kwargs["ports"]:
            cmd.extend(["-ports", ",".join(str(p) for p in kwargs["ports"])])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> List[RawFinding]:
        findings = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url", target)
                status_code = data.get("status_code", 0)
                tech = data.get("tech", [])
                title = data.get("title", "")
                findings.append(RawFinding(
                    tool="httpx",
                    target=target,
                    endpoint=url,
                    vuln_type="live_host",
                    severity="INFO",
                    description=f"HTTP {status_code} on {url} - Title: {title}",
                    raw_output=line,
                    evidence={
                        "status_code": status_code,
                        "tech": tech,
                        "title": title,
                        "content_length": data.get("content_length"),
                        "webserver": data.get("webserver"),
                    },
                ))
            except json.JSONDecodeError:
                continue
        return findings
