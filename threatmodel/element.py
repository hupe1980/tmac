from abc import ABCMeta, abstractproperty
from typing import List, Set
from tabulate import tabulate

from .node import Construct
from .threat import Risk
from .table_format import TableFormat



class Element(Construct, metaclass=ABCMeta):
    """A generic model element"""

    def __init__(self, scope: Construct, name: str, description: str = ""):
        super().__init__(scope, name)

        self.description = description

        # import when need to avoid circular import
        from .model import Model
        self._model = Model.of(self)

    @abstractproperty
    def out_of_scope(self) -> bool:
        pass

    @property
    def risks(self) -> List["Risk"]:
        threatlib = self._model.threatlib
        return threatlib.apply(self)

    def get_risk_by_id(self, id: str) -> "Risk":
        return [risk for risk in self.risks if risk.id == id][0]

    def risks_table(self, table_format: "TableFormat" = TableFormat.SIMPLE) -> str:
        headers = ["SID", "Severity", "Category", "Name", "Treatment"]
        table = []

        for risk in self.risks:
            table.append([risk.id, risk.severity, risk.category,
                         risk.name, risk.treatment])

        return tabulate(table, headers=headers, tablefmt=str(table_format))
