"""Harness Orchestrator: 10-phase assessment state machine integrating all 9 pillars."""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from bughunter.core.session import SessionManager
from bughunter.core.state_machine import PhaseStatus, PhaseContract, new_phases
from bughunter.core.scope import ContinuousScope, ScopeDecision
from bughunter.adapters import get_adapter
from bughunter.harness.memory import HarnessMemory
from bughunter.harness.planner import AIPlanningEngine
from bughunter.harness.payload_engine import AIPayloadEngine
from bughunter.harness.safety_gate import DeterministicSafetyGate
from bughunter.harness.verifier import SelfVerificationEngine, VerificationStatus
from bughunter.harness.recovery import LoopBreaker, CircuitBreakerMonitor, StateCheckpoint
from bughunter.harness.reporter import HarnessReportGenerator


class HarnessOrchestrator:
    """Master orchestrator executing the 10-phase assessment lifecycle."""

    def __init__(
        self,
        session_id: str,
        target: str,
        scope: Optional[ContinuousScope] = None,
        dry_run: bool = False,
        profile: str = "active",
        phase_filter: Optional[str] = None,
        session_manager: Optional[SessionManager] = None,
        brain: Any = None,
    ):
        self.session_id = session_id
        self.target = target
        self.scope = scope or ContinuousScope.default_for_target(target)
        self.dry_run = dry_run
        self.profile = profile
        self.phase_filter = phase_filter
        self.session_manager = session_manager or SessionManager()
        self.brain = brain

        # Pillars initialization
        self.memory = HarnessMemory(target=target)
        self.planner = AIPlanningEngine(brain=self.brain)
        self.payload_engine = AIPayloadEngine(brain=self.brain)
        self.safety_gate = DeterministicSafetyGate()
        self.verifier = SelfVerificationEngine()
        self.loop_breaker = LoopBreaker()
        self.circuit_breaker = CircuitBreakerMonitor()
        self.checkpoint = StateCheckpoint(self.session_manager)
        self.reporter = HarnessReportGenerator(session_id=session_id, target=target)

        # Parse phase filter (e.g., "1-3" or "5")
        self.allowed_phase_numbers = self._parse_phase_filter(phase_filter)

    def _parse_phase_filter(self, phase_filter: Optional[str]) -> Optional[set]:
        if not phase_filter:
            return None
        allowed = set()
        for part in phase_filter.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                allowed.update(range(int(start), int(end) + 1))
            elif part.isdigit():
                allowed.add(int(part))
        return allowed

    def _should_run_phase(self, phase_number: int) -> bool:
        if self.allowed_phase_numbers is None:
            return True
        return phase_number in self.allowed_phase_numbers

    def run(self) -> Dict[str, Any]:
        """Execute full assessment loop across 10 structured phases."""
        state = self.session_manager.load(self.session_id)
        phases_contracts = new_phases()

        # Phase 1: Scope & RoE
        self._execute_phase_1_scope(phases_contracts[0])

        # Phase 2: Passive Recon
        self._execute_phase_2_passive_recon(phases_contracts[1])

        # Phase 3: Active Discovery
        self._execute_phase_3_active_discovery(phases_contracts[2])

        # Phase 4: Application Mapping
        self._execute_phase_4_app_mapping(phases_contracts[3])

        # Phase 5: Surface Analysis
        self._execute_phase_5_surface_analysis(phases_contracts[4])

        # Phase 6: Vulnerability Assessment
        self._execute_phase_6_assessment(phases_contracts[5])

        # Phase 7: Controlled Validation
        self._execute_phase_7_validation(phases_contracts[6])

        # Phase 8: Risk Analysis & Impact
        self._execute_phase_8_risk_analysis(phases_contracts[7])

        # Phase 9: Reporting & Remediation
        self._execute_phase_9_reporting(phases_contracts[8])

        # Phase 10: Retesting (Skipped by default on initial attack)
        self._execute_phase_10_retesting(phases_contracts[9], run_now=False)

        # Update final state
        state = self.session_manager.load(self.session_id)
        return state

    def _transition_phase(self, phase: PhaseContract, new_status: PhaseStatus) -> None:
        phase.transition(new_status)
        self.checkpoint.update_phase(self.session_id, phase.number, phase.status.value)

    # ── Phase 1: Scope & RoE ──────────────────────────────────────────────────
    def _execute_phase_1_scope(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        # Check scope validity
        action_decision = self.scope.validate_action(
            self.target if self.target.startswith("http") else f"http://{self.target}"
        )
        if action_decision != ScopeDecision.ALLOW:
            self._transition_phase(phase, PhaseStatus.BLOCKED)
            raise ValueError(f"Scope check failed for target {self.target}: {action_decision.value}")

        self.memory.working.add_note(f"Scope validated for {self.target}. Private IPs permitted.")
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 2: Passive Recon ───────────────────────────────────────────────
    def _execute_phase_2_passive_recon(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        if not self.dry_run:
            subfinder = get_adapter("subfinder")
            if subfinder and subfinder.is_available():
                findings = subfinder.run(self.target)
                for f in findings:
                    self.memory.add_observation("subfinder", f.description)

        self.memory.working.add_note("Passive recon completed")
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 3: Active Discovery ─────────────────────────────────────────────
    def _execute_phase_3_active_discovery(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        if self.profile == "passive":
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        if not self.dry_run:
            httpx = get_adapter("httpx")
            if httpx and httpx.is_available():
                findings = httpx.run(self.target)
                for f in findings:
                    self.memory.add_observation("httpx", f.description)
                    techs = f.evidence.get("tech", [])
                    for t in techs:
                        if t not in self.memory.working.detected_tech:
                            self.memory.working.detected_tech.append(t)

        self.memory.working.add_note("Active discovery completed")
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 4: Application Mapping ──────────────────────────────────────────
    def _execute_phase_4_app_mapping(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        if not self.dry_run and self.profile == "active":
            katana = get_adapter("katana")
            if katana and katana.is_available():
                findings = katana.run(self.target)
                for f in findings:
                    self.memory.add_observation("katana", f.description)

        self.memory.working.add_note("Application mapping completed")
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 5: Surface Analysis ─────────────────────────────────────────────
    def _execute_phase_5_surface_analysis(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        # Identify high-risk parameters and routes
        self.memory.working.add_hypothesis(f"Analyze attack surface for {self.target}")
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 6: Vulnerability Assessment ─────────────────────────────────────
    def _execute_phase_6_assessment(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        plan = self.planner.plan_phase(
            phase_name="assessment",
            target=self.target,
            detected_tech=self.memory.working.detected_tech,
            observations_context=self.memory.get_prompt_context(),
        )

        for item in plan.plan_items:
            # Check loop breaker before executing each action
            self.loop_breaker.record_and_check(item.action, {"endpoint": item.endpoint})

            if not self.dry_run and item.vulnerability_class:
                # Generate safe probe
                probe = self.payload_engine.generate_probe(item.vulnerability_class)
                # Verify safety gate
                self.safety_gate.check_or_raise(probe.payload)

        self.memory.working.add_note("Vulnerability assessment phase executed")
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 7: Controlled Validation ────────────────────────────────────────
    def _execute_phase_7_validation(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        # Verify findings in memory
        for finding in self.memory.findings:
            res = self.verifier.verify_finding(
                finding=finding.to_dict(),
                in_scope=True,
            )
            finding.verified = (res.status == VerificationStatus.CONFIRMED)

        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 8: Risk Analysis & Impact ───────────────────────────────────────
    def _execute_phase_8_risk_analysis(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        for finding in self.memory.findings:
            if finding.verified:
                score, vector, sev = self.verifier.calculate_cvss_for_finding(finding.to_dict())
                finding.severity = sev
                finding.details["cvss_score"] = score
                finding.details["cvss_vector"] = vector

        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 9: Reporting & Remediation ──────────────────────────────────────
    def _execute_phase_9_reporting(self, phase: PhaseContract) -> None:
        if not self._should_run_phase(phase.number):
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        session_dir = self.session_manager.path(self.session_id)
        reports_dir = session_dir / "reports"

        state = self.session_manager.load(self.session_id)
        verified_data = []
        for f in self.memory.findings:
            d = f.to_dict()
            d["status"] = "CONFIRMED" if f.verified else "INCONCLUSIVE"
            d["cvss_score"] = f.details.get("cvss_score", 0.0)
            d["cvss_vector"] = f.details.get("cvss_vector", "")
            verified_data.append(d)

        self.reporter.save_reports(reports_dir, state, verified_data)
        self.checkpoint.record_findings(self.session_id, verified_data)
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    # ── Phase 10: Retesting & Differential Analysis ───────────────────────────
    def _execute_phase_10_retesting(self, phase: PhaseContract, run_now: bool = False) -> None:
        if not run_now:
            self._transition_phase(phase, PhaseStatus.SKIPPED)
            return

        self._transition_phase(phase, PhaseStatus.RUNNING)
        # Perform retest against previously logged findings
        self._transition_phase(phase, PhaseStatus.COMPLETED)

    def retest(self) -> Dict[str, Any]:
        """Perform differential retesting of existing session findings."""
        from bughunter.phases.p10_retesting import retest_session
        retest_results = retest_session(self.session_id, manager=self.session_manager)
        self.checkpoint.update_phase(self.session_id, 10, PhaseStatus.COMPLETED.value)
        return retest_results
