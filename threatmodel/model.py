from typing import Dict, List, Optional, Set, TYPE_CHECKING
import uuid
from tabulate import tabulate

from .node import Construct
from .risk import Risk, Treatment
from .diagram import SequenceDiagram
from .table_format import TableFormat

if TYPE_CHECKING:
    from .control import Control
    from .threat import Threatlib
    from .trust_boundary import TrustBoundary


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
            # import when need to avoid circular import
            from .threatlib import DEFAULT_THREATLIB
            self.threatlib = DEFAULT_THREATLIB
        else:
            self.threatlib = threatlib

    @property
    def technical_assets(self):
        from .asset import TechnicalAsset
        return list(filter(lambda c: isinstance(c, TechnicalAsset), self.node.find_all()))

    def evaluate(self) -> "Result":
        result = Result(self.title)

        for c in self.node.find_all():
            if isinstance(c, Element):
                result.add_risk(*c.risks)
                result.add_elements(c)

        return result


class Element(Construct):
    """A generic element"""

    def __init__(self, model: Construct, name: str, in_scope: bool = True, trust_boundary: Optional["TrustBoundary"] = None):
        super().__init__(model, name)

        self.name = name
        self.uniq_name = self._uniq_name()
        self.in_scope = in_scope
        self.trust_boundary = trust_boundary

        self._controls: Set["Control"] = set()

    @property
    def risks(self) -> List["Risk"]:
        threatlib = Model.of(self).threatlib
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


class Result:
    def __init__(self, model_title: str) -> None:
        self.model_title = model_title
        self._risks: Dict[str, Risk] = dict()
        self._elements: List[Element] = list()

    def add_risk(self, *risks: Risk) -> None:
        for risk in risks:
            self._risks[risk.id] = risk

    def add_elements(self, *elements: Element) -> None:
        for element in elements:
            self._elements.append(element)

    def risks(self) -> List[Risk]:
        return list(self._risks.values())

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
        # import when need to avoid circular import
        from .asset import ExternalEntity, DataStore, TechnicalAsset
        from .data_flow import DataFlow

        diagram = SequenceDiagram(self.model_title)

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



