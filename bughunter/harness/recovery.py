"""Error recovery, loop prevention, and session resilience engine."""
import json
import time
from typing import Any, Dict, List, Optional, Tuple

from bughunter.agent import LoopDetector
from bughunter.core.policy_engine import PolicyEngine
from bughunter.core.session import SessionManager


class LoopDetectedError(RuntimeError):
    """Raised when an agent enters an unrecoverable repetitive execution loop."""
    pass


class TargetUnresponsiveError(RuntimeError):
    """Raised when target server consistently returns 5xx errors exceeding threshold."""
    pass


class LoopBreaker:
    """Sliding-window loop detector that forces replanning or aborts stuck execution."""
    def __init__(self, warn_at: int = 3, break_at: int = 5):
        self._detector = LoopDetector()
        self.warn_at = warn_at
        self.break_at = break_at
        self._repeated_call_count = 0

    def record_and_check(self, action_name: str, parameters: Dict[str, Any]) -> Tuple[bool, bool]:
        """
        Record tool call signature. Returns (warn, must_break).
        Raises LoopDetectedError if loop repetition exceeds break_at.
        """
        warn, must_break = self._detector.record(action_name, parameters)
        if must_break:
            raise LoopDetectedError(
                f"Agent stalled: repeated '{action_name}' {self.break_at} times with identical parameters. "
                "Forced abort to prevent infinite loop."
            )
        return warn, must_break

    def reset(self) -> None:
        self._detector.reset()


class CircuitBreakerMonitor:
    """Monitors HTTP responses and coordinates backoff when target server fails."""
    def __init__(self, policy: Optional[PolicyEngine] = None, max_consecutive_5xx: int = 5):
        self.policy = policy or PolicyEngine(error_threshold=max_consecutive_5xx)
        self.max_5xx = max_consecutive_5xx
        self.consecutive_errors = 0

    def record_status(self, status_code: int) -> None:
        self.policy.record(status_code)
        if status_code >= 500:
            self.consecutive_errors += 1
            if self.consecutive_errors >= self.max_5xx:
                raise TargetUnresponsiveError(
                    f"Target server returned {self.consecutive_errors} consecutive 5xx responses. Circuit breaker triggered."
                )
        else:
            self.consecutive_errors = 0


class StateCheckpoint:
    """Atomic session state management and recovery."""
    def __init__(self, session_manager: Optional[SessionManager] = None):
        self.manager = session_manager or SessionManager()

    def update_phase(self, session_id: str, phase_number: int, new_status: str) -> Dict[str, Any]:
        state = self.manager.load(session_id)
        for p in state.get("phases", []):
            if p.get("number") == phase_number:
                p["status"] = new_status
                break
        self.manager.save(state)
        return state

    def record_findings(self, session_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        state = self.manager.load(session_id)
        if "findings" not in state:
            state["findings"] = []
        state["findings"].extend(findings)
        self.manager.save(state)
        return state

    def load_state(self, session_id: str) -> Dict[str, Any]:
        return self.manager.load(session_id)
