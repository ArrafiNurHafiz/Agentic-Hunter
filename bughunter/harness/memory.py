"""Three-layer context and memory engine for AI Agent Harness."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional

try:
    from memory.redaction import redact_obj
except ImportError:
    try:
        from bughunter.memory.redaction import redact_obj
    except ImportError:
        def redact_obj(obj):
            return obj


@dataclass
class WorkingMemory:
    target: str
    current_phase: str = "scope"
    notes: List[str] = field(default_factory=list)
    active_hypotheses: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    detected_tech: List[str] = field(default_factory=list)

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def add_hypothesis(self, hypothesis: str) -> None:
        if hypothesis not in self.active_hypotheses:
            self.active_hypotheses.append(hypothesis)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "current_phase": self.current_phase,
            "notes": self.notes[-20:],  # keep recent
            "active_hypotheses": self.active_hypotheses,
            "next_steps": self.next_steps,
            "detected_tech": self.detected_tech,
        }


@dataclass
class Observation:
    tool: str
    summary: str
    count: int = 1
    raw_refs: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "summary": self.summary,
            "count": self.count,
            "raw_refs": self.raw_refs,
            "timestamp": self.timestamp,
        }


@dataclass
class FindingRecord:
    finding_id: str
    title: str
    severity: str
    vuln_type: str
    endpoint: str
    evidence_hash: str
    verified: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "evidence_hash": self.evidence_hash,
            "verified": self.verified,
            "details": self.details,
            "timestamp": self.timestamp,
        }


class ContextCompactor:
    """Sliding-window compactor ensuring prompt efficiency for 9Router LLM backend."""
    def __init__(self, max_chars: int = 12000):
        self.max_chars = max_chars

    def compact(self, working: WorkingMemory, observations: List[Observation], findings: List[FindingRecord]) -> str:
        sections = []

        # Working state
        sections.append(f"### CURRENT TARGET: {working.target} (Phase: {working.current_phase})")
        if working.detected_tech:
            sections.append(f"Detected Tech: {', '.join(working.detected_tech)}")
        if working.active_hypotheses:
            sections.append(f"Active Hypotheses:\n" + "\n".join(f"- {h}" for h in working.active_hypotheses))
        if working.notes:
            recent_notes = working.notes[-5:]
            sections.append(f"Recent Notes:\n" + "\n".join(f"- {n}" for n in recent_notes))

        # Compact findings summary
        if findings:
            f_summary = []
            for f in findings:
                status = "CONFIRMED" if f.verified else "UNVERIFIED"
                f_summary.append(f"[{f.severity}] {f.title} @ {f.endpoint} ({status})")
            sections.append("Verified Findings:\n" + "\n".join(f_summary))

        # Recent Observations (most recent first)
        if observations:
            obs_lines = []
            for o in observations[-15:]:
                obs_lines.append(f"- [{o.tool}] {o.summary}")
            sections.append("Recent Observations:\n" + "\n".join(obs_lines))

        full_text = "\n\n".join(sections)
        # Redact any accidental tokens/secrets
        redacted = redact_obj(full_text)
        if isinstance(redacted, str):
            full_text = redacted

        if len(full_text) > self.max_chars:
            # Keep header and tail
            head = full_text[: self.max_chars // 3]
            tail = full_text[- (self.max_chars * 2 // 3):]
            full_text = head + "\n\n... [older context summarized/truncated for token efficiency] ...\n\n" + tail

        return full_text


class HarnessMemory:
    def __init__(self, target: str):
        self.working = WorkingMemory(target=target)
        self.observations: List[Observation] = []
        self.findings: List[FindingRecord] = []
        self.compactor = ContextCompactor()

    def add_observation(self, tool: str, summary: str, raw_refs: Optional[List[str]] = None) -> None:
        obs = Observation(tool=tool, summary=summary, raw_refs=raw_refs or [])
        self.observations.append(obs)

    def add_finding(self, title: str, severity: str, vuln_type: str, endpoint: str,
                    raw_evidence: Any, verified: bool = False, details: Optional[Dict[str, Any]] = None) -> FindingRecord:
        # Generate sha256 hash of evidence for forensic integrity
        serialized = json.dumps(raw_evidence, sort_keys=True, default=str).encode()
        ev_hash = hashlib.sha256(serialized).hexdigest()
        f_id = f"fnd_{ev_hash[:10]}"
        rec = FindingRecord(
            finding_id=f_id,
            title=title,
            severity=severity.upper(),
            vuln_type=vuln_type,
            endpoint=endpoint,
            evidence_hash=ev_hash,
            verified=verified,
            details=details or {},
        )
        self.findings.append(rec)
        return rec

    def get_prompt_context(self) -> str:
        return self.compactor.compact(self.working, self.observations, self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "working": self.working.to_dict(),
            "observations": [o.to_dict() for o in self.observations],
            "findings": [f.to_dict() for f in self.findings],
        }
