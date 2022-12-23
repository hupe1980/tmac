from typing import Any
from .node import Construct
from .otm import OpenThreatModelMitigation


class Mitigation(Construct):
    def __init__(self, scope: Construct, name: str, description: str = "", risk_reduction: int = 0) -> None:
        super().__init__(scope, name)
        
        self.description = description
        self.risk_reduction = risk_reduction

    @property
    def otm(self) -> "OpenThreatModelMitigation":
        return OpenThreatModelMitigation(
            name=self.name,
            id=self.id,
            description=self.description,
            risk_reduction=self.risk_reduction,
        )


class FalsePositive(Mitigation):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(name="False positive", risk_reduction=100, **kwargs)
