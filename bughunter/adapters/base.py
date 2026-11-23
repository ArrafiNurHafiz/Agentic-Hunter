"""Base classes and manifests for external scanner adapters."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import json
import shutil
from typing import Any, Dict, List, Optional
import subprocess

from bughunter.core.executor import run_command


class AdapterMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


@dataclass
class CapabilityManifest:
    name: str
    mode: AdapterMode
    timeout: int = 60
    rate_limit_cost: int = 1
    supported_targets: List[str] = field(default_factory=lambda: ["domain", "ip", "url"])
    description: str = ""


@dataclass
class RawFinding:
    tool: str
    target: str
    endpoint: str = ""
    vuln_type: str = ""
    severity: str = "INFO"
    description: str = ""
    raw_output: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "target": self.target,
            "endpoint": self.endpoint,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "description": self.description,
            "raw_output": self.raw_output,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


class BaseScannerAdapter(ABC):
    def __init__(self, manifest: CapabilityManifest):
        self.manifest = manifest

    @abstractmethod
    def build_command(self, target: str, **kwargs) -> List[str]:
        """Construct subprocess argv for the scanner."""
        pass

    @abstractmethod
    def parse_output(self, raw_output: str, target: str) -> List[RawFinding]:
        """Parse raw scanner stdout/stderr into normalized RawFinding instances."""
        pass

    def is_available(self) -> bool:
        """Check if binary tool is available on PATH."""
        return shutil.which(self.manifest.name) is not None

    def run(self, target: str, **kwargs) -> List[RawFinding]:
        """Execute scanner command with timeout and error isolation."""
        argv = self.build_command(target, **kwargs)
        timeout = kwargs.get("timeout", self.manifest.timeout)
        try:
            completed = run_command(argv, timeout=timeout)
            return self.parse_output(completed.stdout or "", target)
        except subprocess.TimeoutExpired:
            return [RawFinding(
                tool=self.manifest.name,
                target=target,
                vuln_type="scan_timeout",
                severity="INFO",
                description=f"Scanner {self.manifest.name} timed out after {timeout}s",
            )]
        except Exception as e:
            return [RawFinding(
                tool=self.manifest.name,
                target=target,
                vuln_type="scan_error",
                severity="INFO",
                description=f"Scanner {self.manifest.name} execution failed: {e}",
            )]
