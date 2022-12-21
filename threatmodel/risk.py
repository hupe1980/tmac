from typing import Optional, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from .element import Element
    from .threat import Threat


class Impact(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very-high"

    def __str__(self) -> str:
        return str(self.value)


class Likelihood(Enum):
    UNLIKELY = "unlikely"
    LIKELY = "likely"
    VERY_LIKELY = "very-likely"
    FREQUENT = "frequent"

    def __str__(self) -> str:
        return str(self.value)


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    ELEVATED = "elevated"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return str(self.value)


class Treatment(Enum):
    UNCHECKED = "unchecked"
    IN_DISCUSSION = "in-discussion"
    IN_PROGRESS = "in-progress",
    MITIGATED = "mitigated"
    TRANSFERRED = "transferred"
    AVOIDED = "avoided"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false-positive"

    def __str__(self) -> str:
        return str(self.value)


class Risk:
    def __init__(self, element: "Element", threat: "Threat",
                 impact: "Impact",
                 likelihood: "Likelihood",
                 fix_severity: Optional["Severity"] = None,
                 treatment: Treatment = Treatment.UNCHECKED,
                 ) -> None:
        self.id = f"{threat.id}@{element.name}"
        self.target = element.name
        self.category = threat.category
        self.name = threat.name
        self.description = threat.description
        self.impact = impact
        self.likelihood = likelihood
        self.prerequisites = threat.prerequisites
        self.mitigations = threat.mitigations

        if fix_severity is None:
            self.severity = self._calculate_severity(impact, likelihood)
        else:
            self.severity = fix_severity

        self._treatment = treatment

    @property
    def treatment(self) -> Treatment:
        return self._treatment

    def treat(self, treatment: Treatment) -> None:
        self._treatment = treatment

    def _calculate_severity(self, impact: "Impact", likelihood: "Likelihood") -> "Severity":
        impact_weights = {Impact.LOW: 1, Impact.MEDIUM: 2,
                          Impact.HIGH: 3, Impact.VERY_HIGH: 4}
        likelihood_weights = {Likelihood.UNLIKELY: 1, Likelihood.LIKELY: 2,
                              Likelihood.VERY_LIKELY: 3, Likelihood.FREQUENT: 4}

        result = likelihood_weights[likelihood] * impact_weights[impact]

        if result <= 1:
            return Severity.LOW

        if result <= 3:
            return Severity.MEDIUM

        if result <= 8:
            return Severity.ELEVATED

        if result <= 12:
            return Severity.HIGH

        return Severity.CRITICAL

    def __repr__(self):
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self) -> str:
        return f"'{self.id}': {self.name}\n{self.description}\n{self.severity}"
