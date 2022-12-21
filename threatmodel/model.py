from typing import Dict, List, Optional, TYPE_CHECKING, cast
from tabulate import tabulate

from .asset import TechnicalAsset
from .element import Element
from .node import Construct
from .data_flow import DataFlow
from .common import is_notebook, is_ci
from .diagram import DataFlowDiagram
from .table_format import TableFormat
from .threatlib import DEFAULT_THREATLIB

if TYPE_CHECKING:
    from .threat import Threat, Threatlib
    from .risk import Risk, Treatment


class Model(Construct):
    @staticmethod
    def of(construct: "Construct") -> "Model":
        def lookup(c: "Construct") -> "Model":
            if isinstance(c, Model):
                return c

            if c.node.scope is None:
                raise ValueError(
                    "No model could be identified for the construct at path"
                )

            return lookup(c.node.scope)

        return lookup(construct)

    def __init__(self, title: str, threatlib: Optional["Threatlib"] = None) -> None:
        super().__init__(None, "")

        self.title = title

        if threatlib is None:
            self.threatlib = DEFAULT_THREATLIB
        else:
            self.threatlib = threatlib

    @property
    def technical_assets(self) -> List["TechnicalAsset"]:
        return cast(List["TechnicalAsset"], list(filter(lambda c: isinstance(c, TechnicalAsset), self.node.find_all())))

    @property
    def data_flows(self) -> List["DataFlow"]:
        return cast(List["DataFlow"], list(filter(lambda c: isinstance(c, DataFlow), self.node.find_all())))
    
    def evaluate(self) -> "Result":
        result = Result(self)

        for c in self.node.find_all():
            if isinstance(c, Element):
                result.add_risk(*c.risks)
                result.add_elements(c)

        return result

    def is_notebook(self) -> bool:
        return is_notebook()

    def is_ci(self) -> bool:
        return is_ci()


class Result:
    def __init__(self, model: "Model") -> None:
        self._model = model
        self._risks: Dict[str, "Risk"] = dict()
        self._elements: List["Element"] = list()

    def add_risk(self, *risks: "Risk") -> None:
        for risk in risks:
            self._risks[risk.id] = risk

    def add_elements(self, *elements: "Element") -> None:
        for element in elements:
            self._elements.append(element)

    @property
    def technical_assets(self) -> List["TechnicalAsset"]:
        return cast(List["TechnicalAsset"], list(filter(lambda c: isinstance(c, TechnicalAsset), self._elements)))

    @property
    def data_flows(self) -> List["DataFlow"]:
        return cast(List["DataFlow"], list(filter(lambda c: isinstance(c, DataFlow), self._elements)))

    @property
    def risks(self) -> List["Risk"]:
        return list(self._risks.values())

    def get_threat_by_id(self, id: str) -> Optional["Threat"]:
        return self._model.threatlib.get(id)

    def get_risk_by_id(self, id: str) -> "Risk":
        return self._risks[id]

    def treat_risk(self, id: str, treatment: "Treatment") -> None:
        self._risks[id].treat(treatment)

    def risks_table(self, table_format: TableFormat = TableFormat.SIMPLE) -> str:
        headers = ["SID", "Severity", "Category",
                   "Name", "Affected", "Treatment"]
        table = []
        for risk in self._risks.values():
            table.append([risk.id, risk.severity, risk.category, risk.name,
                         risk.target, risk.treatment])

        return tabulate(table, headers=headers, tablefmt=str(table_format))

    def data_flow_diagram(self, auto_view = True):
        diagram = DataFlowDiagram(self._model.title)

        for e in self._elements:
            if isinstance(e, DataFlow):
                diagram.add_data_flow(e.source.uniq_name, e.sink.uniq_name, f"{e.protocol}: {e.name}", **e.overwrite_edge_attrs)
                continue
            if isinstance(e, TechnicalAsset):
                diagram.add_asset(e.uniq_name, e.name, e.shape, **e.overwrite_node_attrs)

        if auto_view is False or self._model.is_ci():
            diagram.save()
            return

        if self._model.is_notebook():
            from IPython import display
            display.display(diagram)
        else:
            diagram.view()
