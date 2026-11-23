"""Nmap port scanning and service detection adapter."""
import re
from typing import List
from bughunter.adapters.base import BaseScannerAdapter, CapabilityManifest, AdapterMode, RawFinding


class NmapAdapter(BaseScannerAdapter):
    def __init__(self):
        super().__init__(CapabilityManifest(
            name="nmap",
            mode=AdapterMode.ACTIVE,
            timeout=180,
            rate_limit_cost=5,
            supported_targets=["domain", "ip"],
            description="Network port scanner and service version detector",
        ))

    def build_command(self, target: str, **kwargs) -> List[str]:
        host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        ports = kwargs.get("ports", "top-100")
        cmd = ["nmap", "-sV", "-Pn", "--open", "-T4", host]
        if ports == "top-100":
            cmd.extend(["--top-ports", "100"])
        elif isinstance(ports, str):
            cmd.extend(["-p", ports])
        elif isinstance(ports, (list, tuple)):
            cmd.extend(["-p", ",".join(str(p) for p in ports)])
        return cmd

    def parse_output(self, raw_output: str, target: str) -> List[RawFinding]:
        findings = []
        # Pattern for standard nmap output: 80/tcp open http Apache httpd 2.4.41
        port_pattern = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)\s*(.*)$", re.MULTILINE)
        for match in port_pattern.finditer(raw_output):
            port, proto, state, service, version = match.groups()
            if state.lower() == "open":
                findings.append(RawFinding(
                    tool="nmap",
                    target=target,
                    endpoint=f"{target}:{port}",
                    vuln_type="open_port",
                    severity="INFO",
                    description=f"Open port {port}/{proto} ({service} {version})".strip(),
                    raw_output=match.group(0),
                    evidence={
                        "port": int(port),
                        "protocol": proto,
                        "state": state,
                        "service": service,
                        "version": version.strip(),
                    },
                ))
        return findings
