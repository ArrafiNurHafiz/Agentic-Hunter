"""Explicit assessment phase states and legal transitions."""
from dataclasses import dataclass
from enum import Enum


class PhaseStatus(str, Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    BLOCKED = 'blocked'
    FAILED = 'failed'
    SKIPPED = 'skipped'
    NEEDS_REVIEW = 'needs_review'


TRANSITIONS = {
    PhaseStatus.PENDING: {PhaseStatus.RUNNING, PhaseStatus.SKIPPED, PhaseStatus.BLOCKED},
    PhaseStatus.RUNNING: {PhaseStatus.COMPLETED, PhaseStatus.FAILED, PhaseStatus.NEEDS_REVIEW},
    PhaseStatus.NEEDS_REVIEW: {PhaseStatus.RUNNING, PhaseStatus.BLOCKED},
    PhaseStatus.FAILED: {PhaseStatus.RUNNING},
}


@dataclass
class PhaseContract:
    number: int
    name: str
    status: PhaseStatus = PhaseStatus.PENDING

    def transition(self, status: PhaseStatus) -> None:
        status = PhaseStatus(status)
        if status not in TRANSITIONS.get(self.status, set()):
            raise ValueError(f'invalid transition {self.status.value} -> {status.value}')
        self.status = status


PHASE_NAMES = ('scope', 'passive_recon', 'active_discovery', 'app_mapping',
               'surface_analysis', 'assessment', 'validation', 'risk_analysis',
               'reporting', 'retesting')


def new_phases():
    return [PhaseContract(i, name) for i, name in enumerate(PHASE_NAMES, 1)]
