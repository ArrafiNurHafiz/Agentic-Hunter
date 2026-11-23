"""AI Planning Engine for dynamic assessment task generation."""
from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional


@dataclass
class PlanItem:
    id: str
    action: str
    endpoint: str = ""
    vulnerability_class: str = ""
    rationale: str = ""
    priority: str = "MEDIUM"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "action": self.action,
            "endpoint": self.endpoint,
            "vulnerability_class": self.vulnerability_class,
            "rationale": self.rationale,
            "priority": self.priority,
        }


@dataclass
class DynamicTestPlan:
    phase: str
    target_asset: str
    detected_tech: List[str] = field(default_factory=list)
    plan_items: List[PlanItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "target_asset": self.target_asset,
            "detected_tech": self.detected_tech,
            "plan_items": [item.to_dict() for item in self.plan_items],
        }


class AIPlanningEngine:
    """Orchestrates dynamic testing plans via 9Router Brain backend with deterministic fallbacks."""

    def __init__(self, brain=None):
        self.brain = brain

    def plan_phase(self, phase_name: str, target: str, detected_tech: Optional[List[str]] = None,
                   observations_context: str = "") -> DynamicTestPlan:
        tech = detected_tech or []

        # Attempt to prompt LLM (9Router) if available
        if self.brain and getattr(self.brain, "available", False):
            try:
                system_prompt = (
                    "You are the AI Planning Engine of BugHunter v3.2. "
                    "Create a structured, non-destructive security test plan in JSON format. "
                    "Output ONLY valid JSON matching this schema: "
                    '{"phase": "...", "target_asset": "...", "detected_tech": [...], '
                    '"plan_items": [{"id": "...", "action": "...", "endpoint": "...", "rationale": "...", "priority": "HIGH|MEDIUM|LOW"}]}'
                )
                user_prompt = (
                    f"Phase: {phase_name}\n"
                    f"Target: {target}\n"
                    f"Detected Technologies: {json.dumps(tech)}\n"
                    f"Observations Context:\n{observations_context}\n"
                )
                resp = self.brain.chat(system=system_prompt, user=user_prompt)
                match = re.search(r"\{.*\}", resp, re.DOTALL)
                if match:
                    parsed = json.loads(match.group(0))
                    items = [PlanItem(**i) for i in parsed.get("plan_items", [])]
                    return DynamicTestPlan(
                        phase=phase_name,
                        target_asset=target,
                        detected_tech=parsed.get("detected_tech", tech),
                        plan_items=items,
                    )
            except Exception:
                pass  # Fall back to deterministic plan

        return self._generate_deterministic_plan(phase_name, target, tech)

    def _generate_deterministic_plan(self, phase_name: str, target: str, tech: List[str]) -> DynamicTestPlan:
        items: List[PlanItem] = []
        p_name = phase_name.lower()

        if "passive_recon" in p_name:
            items.append(PlanItem(id="pr_1", action="run_subdomain_enum", endpoint=target,
                                  rationale="Enumerate subdomains via passive sources", priority="HIGH"))
        elif "active_discovery" in p_name:
            items.append(PlanItem(id="ad_1", action="run_port_scan", endpoint=target,
                                  rationale="Identify active TCP services and HTTP ports", priority="HIGH"))
            items.append(PlanItem(id="ad_2", action="run_http_probe", endpoint=target,
                                  rationale="Detect live HTTP hosts and web technologies", priority="HIGH"))
        elif "app_mapping" in p_name:
            items.append(PlanItem(id="am_1", action="run_crawler", endpoint=target,
                                  rationale="Map endpoints, forms, and routes", priority="MEDIUM"))
        elif "surface_analysis" in p_name:
            items.append(PlanItem(id="sa_1", action="rank_attack_surface", endpoint=target,
                                  rationale="Score attack surface parameters and auth gates", priority="MEDIUM"))
        elif "assessment" in p_name:
            # Tech-tailored assessment tasks
            if any("laravel" in t.lower() or "php" in t.lower() for t in tech):
                items.append(PlanItem(id="as_1", action="run_api_fuzz", endpoint=f"{target}/api",
                                      vulnerability_class="IDOR",
                                      rationale="Check REST API endpoints for IDOR and parameter tampering", priority="HIGH"))
            items.append(PlanItem(id="as_2", action="run_vuln_scan", endpoint=target,
                                  rationale="Run non-destructive signature and template scans", priority="MEDIUM"))
        elif "validation" in p_name:
            items.append(PlanItem(id="vl_1", action="verify_findings", endpoint=target,
                                  rationale="Self-verify discovered anomalies using 7-Question Gate", priority="HIGH"))
        elif "reporting" in p_name:
            items.append(PlanItem(id="rp_1", action="generate_report", endpoint=target,
                                  rationale="Synthesize validated findings into Markdown and JSON reports", priority="HIGH"))
        elif "retesting" in p_name:
            items.append(PlanItem(id="rt_1", action="retest_findings", endpoint=target,
                                  rationale="Differential retesting against previous session baseline", priority="HIGH"))
        else:
            items.append(PlanItem(id="gn_1", action="evaluate_scope", endpoint=target,
                                  rationale="Confirm authorization bounds and active target parameters", priority="HIGH"))

        return DynamicTestPlan(phase=phase_name, target_asset=target, detected_tech=tech, plan_items=items)

    def replan_with_new_leads(self, current_plan: DynamicTestPlan, new_leads: List[Dict[str, Any]]) -> DynamicTestPlan:
        """Inject newly discovered high-priority endpoints into the active plan."""
        existing_endpoints = {item.endpoint for item in current_plan.plan_items}
        for idx, lead in enumerate(new_leads):
            ep = lead.get("endpoint", "")
            if ep and ep not in existing_endpoints:
                current_plan.plan_items.insert(0, PlanItem(
                    id=f"replan_{idx}",
                    action=lead.get("suggested_action", "run_diagnostic_probe"),
                    endpoint=ep,
                    vulnerability_class=lead.get("vuln_class", ""),
                    rationale=f"Dynamic replan lead: {lead.get('reason', 'discovered endpoint')}",
                    priority="HIGH",
                ))
                existing_endpoints.add(ep)
        return current_plan
