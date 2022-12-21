from typing import Dict, List, Optional, TYPE_CHECKING, cast
from tabulate import tabulate

from .asset import ExternalEntity, DataStore, TechnicalAsset
from .data_flow import DataFlow
from .element import Element
from .node import Construct
from .risk import Risk, Treatment
from .diagram import SequenceDiagram
from .table_format import TableFormat
from .threatlib import DEFAULT_THREATLIB

if TYPE_CHECKING:
    from .threat import Threat, Threatlib


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
    def technical_assets(self)-> List["TechnicalAsset"]:
        return cast(List["TechnicalAsset"], list(filter(lambda c: isinstance(c, TechnicalAsset), self.node.find_all())))

    def evaluate(self) -> "Result":
        result = Result(self)

        for c in self.node.find_all():
            if isinstance(c, Element):
                result.add_risk(*c.risks)
                result.add_elements(c)

        return result


class Result:
    def __init__(self, model: Model) -> None:
        self._model = model
        self._risks: Dict[str, Risk] = dict()
        self._elements: List[Element] = list()

    def add_risk(self, *risks: Risk) -> None:
        for risk in risks:
            self._risks[risk.id] = risk

    def add_elements(self, *elements: Element) -> None:
        for element in elements:
            self._elements.append(element)

    @property
    def technical_assets(self)-> List["TechnicalAsset"]:
        return cast(List["TechnicalAsset"], list(filter(lambda c: isinstance(c, TechnicalAsset), self._elements)))
    
    @property
    def risks(self) -> List[Risk]:
        return list(self._risks.values())

    def get_threat_by_id(self, id: str) -> Optional["Threat"]:
        return self._model.threatlib.get(id)

    def get_risk_by_id(self, id: str) -> Risk:
        return self._risks[id]

    def treat_risk(self, id: str, treatment: Treatment) -> None:
        self._risks[id].treat(treatment)

    def risks_table(self, table_format: TableFormat = TableFormat.SIMPLE) -> str:
        headers = ["SID", "Severity", "Category",
                   "Name", "Affected", "Treatment"]
        table = []
        for risk in self._risks.values():
            table.append([risk.id, risk.severity, risk.category, risk.name,
                         risk.target, risk.treatment])

        return tabulate(table, headers=headers, tablefmt=str(table_format))

    def sequence_diagram(self) -> str:
        diagram = SequenceDiagram(self._model.title)

        for e in self._elements:
            if isinstance(e, DataFlow):
                for data in e.data_sent:
                    diagram.add_message(e.source.uniq_name,
                                        e.sink.uniq_name, data.name)
                for data in e.data_received:
                    diagram.add_message(
                        e.sink.uniq_name, e.source.uniq_name, data.name)
                continue

            if isinstance(e, ExternalEntity):
                diagram.add_actor(e.uniq_name, e.name)
                continue

            if isinstance(e, DataStore):
                diagram.add_database(e.uniq_name, e.name)
                continue

            if isinstance(e, TechnicalAsset):
                diagram.add_entity(e.uniq_name, e.name)
                continue

        return diagram.render()
