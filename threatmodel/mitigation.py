from typing import Any, Set, TYPE_CHECKING
from enum import Enum

from .node import Construct
from .otm import OpenThreatModelMitigation

if TYPE_CHECKING:
    from .threat import Risk


class ImplementationState(Enum):
    DRAFT = "draft"
    IN_PROGRESS = "in-progress"
    IMPLEMENTET = "implementet"
    


class Mitigation(Construct):
    def __init__(self, scope: Construct, name: str, risk_reduction: int, description: str = "", state: "ImplementationState" = ImplementationState.DRAFT) -> None:
        super().__init__(scope, name)

        self.description = description
        self.risk_reduction = risk_reduction
        self._risk_ids: Set[str] = set()
        self._state = state

    def treats(self, risk: "Risk") -> None:
        self._risk_ids.add(risk.id)

    def is_applicable(self, risk_id: str) -> bool:
        return risk_id in self._risk_ids

    def update_state(self, new_state: "ImplementationState") -> None:
        self._state = new_state

    @property
    def state(self) -> ImplementationState:
        return self._state

    @property
    def otm(self) -> "OpenThreatModelMitigation":
        return OpenThreatModelMitigation(
            name=self.name,
            id=self.id,
            description=self.description,
            risk_reduction=self.risk_reduction,
        )


class Accept(Mitigation):
    def __init__(self, scope: Construct, **kwargs: Any) -> None:
        super().__init__(scope, "Accept", risk_reduction=100, **kwargs)


class Transfer(Mitigation):
    def __init__(self, scope: Construct, **kwargs: Any) -> None:
        super().__init__(scope, "Transfer", risk_reduction=100, **kwargs)


class FalsePositive(Mitigation):
    def __init__(self, scope: Construct, **kwargs: Any) -> None:
        super().__init__(scope, "False positive", risk_reduction=100, **kwargs)
