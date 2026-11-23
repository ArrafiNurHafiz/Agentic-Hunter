"""Interface for an assessment phase."""
from abc import ABC, abstractmethod


class BasePhase(ABC):
    @abstractmethod
    def run(self, session):
        """Execute the phase and return its artifacts."""
