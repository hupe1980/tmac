from typing import Set, Optional, TYPE_CHECKING
from enum import Enum

from .mitigation import Mitigation, Accept, FalsePositive

if TYPE_CHECKING:
    from .element import Element
    from .threat import Threat


class Impact(Enum):
    VERY_LOW = "very-low"
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
    MITIGATED = "mitigated"
    TRANSFERRED = "transferred"
    AVOIDED = "avoided"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false-positive"

    def __str__(self) -> str:
        return str(self.value)


class Risk:
    def __init__(
        self,
        element: "Element",
        threat: "Threat",
        impact: "Impact",
        likelihood: "Likelihood",
        fix_severity: Optional["Severity"] = None,
    ) -> None:
        self.id: str = f"{threat.id}@{element.name}"
        self.target = element.name
        self.category = threat.category
        self.name = threat.name
        self.description = threat.description
        self.impact = impact
        self.likelihood = likelihood

        self._elemet = element
        self._threat = threat

        if fix_severity is None:
            self.severity = self._calculate_severity(impact, likelihood)
        else:
            self.severity = fix_severity

        self._treatment = Treatment.UNCHECKED

        self._mitigations: Set["Mitigation"] = set()

        self._inherent_risk = ""
        self._current_risk = ""
        self._projected_risk = ""

    @property
    def treatment(self) -> Treatment:
        treatment = Treatment.UNCHECKED
        for mitigation in self._mitigations:
            if isinstance(mitigation, Accept):
                treatment = Treatment.ACCEPTED
                break
            if isinstance(mitigation, Mitigation):  # TODO: risk_reduction, state
                treatment = Treatment.MITIGATED
                break

        return treatment

    @property
    def max_average_asset_score(self) -> float:
        return self._elemet.max_average_asset_score

    def add_mitigations(self, *mitigations: "Mitigation") -> None:
        for m in mitigations:
            self._mitigations.add(m)

    def _calculate_severity(
        self, impact: "Impact", likelihood: "Likelihood"
    ) -> "Severity":
        impact_weights = {
            Impact.LOW: 1,
            Impact.MEDIUM: 2,
            Impact.HIGH: 3,
            Impact.VERY_HIGH: 4,
        }
        likelihood_weights = {
            Likelihood.UNLIKELY: 1,
            Likelihood.LIKELY: 2,
            Likelihood.VERY_LIKELY: 3,
            Likelihood.FREQUENT: 4,
        }

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

    def __repr__(self) -> str:
        return "<{0}.{1}({2}) at {3}>".format(
            self.__module__, type(self).__name__, self.id, hex(id(self))
        )

    def __str__(self) -> str:
        return f"'{self.id}': {self.name}\n{self.description}\n{self.severity}"


class RiskCalculator:
    def __init__(
        self,
        asset_value_weighting: float = 1,
        ease_of_exploitation_weighting: float = 1,
        exposure_weighting: float = 1,
        business_impact_weighting: float = 1,
    ) -> None:
        self._asset_value_weighting = asset_value_weighting
        self._ease_of_exploitation_weighting = ease_of_exploitation_weighting
        self._exposure_weighting = exposure_weighting
        self._business_impact_weighting = business_impact_weighting

    def calculate_risk(self, risk: "Risk") -> None:
        # TODO inherent -> threat_impact * self._business_impact_weighting / 100 + (risk.max_average_asset_score * self._asset_value_weighting)
        # return (inherent, current, calculatet)
        pass
