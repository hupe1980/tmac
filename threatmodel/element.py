from typing import List, Optional, Set, TYPE_CHECKING
import uuid
from tabulate import tabulate

from .node import Construct
from .risk import Risk
from .table_format import TableFormat

if TYPE_CHECKING:
    from .control import Control
    from .trust_boundary import TrustBoundary


class Element(Construct):
    """A generic element"""

    def __init__(self, model: Construct, name: str, in_scope: bool = True, trust_boundary: Optional["TrustBoundary"] = None):
        super().__init__(model, name)

        self.name = name
        self.uniq_name = self._uniq_name()
        self.in_scope = in_scope
        self.trust_boundary = trust_boundary

        self._controls: Set["Control"] = set()

        # import when need to avoid circular import
        from .model import Model
        self._model = Model.of(self)

    @property
    def risks(self) -> List["Risk"]:
        threatlib = self._model.threatlib
        return threatlib.apply(self)

    @property
    def controls(self) -> Set["Control"]:
        return self._controls

    def add_controls(self, *controls: "Control") -> None:
        for control in controls:
            self._controls.add(control)

    def remove_controls(self, *controls: "Control") -> None:
        for control in controls:
            self._controls.remove(control)

    def has_control(self, control: "Control") -> bool:
        return control in self._controls

    def has_controls(self, *controls: "Control") -> bool:
        return set(controls).issubset(self._controls)

    def has_at_least_one_of_the_controls(self, *controls: "Control") -> bool:
        return len(self._controls.intersection(controls)) > 0

    def get_risk_by_id(self, id: str) -> "Risk":
        return [risk for risk in self.risks if risk.id == id][0]

    def risks_table(self, table_format: "TableFormat" = TableFormat.SIMPLE) -> str:
        headers = ["SID", "Severity", "Category", "Name", "Treatment"]
        table = []

        for risk in self.risks:
            table.append([risk.id, risk.severity, risk.category,
                         risk.name, risk.treatment])

        return tabulate(table, headers=headers, tablefmt=str(table_format))

    def _uniq_name(self) -> str:
        uid = str(uuid.uuid4())[:8]
        return f"{self.name}_{uid}"