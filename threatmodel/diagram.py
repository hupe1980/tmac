from typing import List, TYPE_CHECKING
import graphviz

from .asset import ExternalEntity, DataStore, TechnicalAsset
from .data_flow import DataFlow


if TYPE_CHECKING:
    from .element import Element


class DataFlowDiagram(graphviz.Digraph):
    def __init__(self, title: str, elements: List["Element"]) -> None:
        super().__init__(title, engine='fdp')

        self.attr("graph", fontname="Arial", fontsize="12", overlap="false")
        self.attr("node", fontname="Arial", fontsize="12",
                  rankdir="lr", margin="0.02")

        for e in elements:
            if isinstance(e, DataFlow):
                self.edge(e.source.uniq_name, e.sink.uniq_name, f"{e.protocol}: {e.name}", 
                    fontname="Arial",
                    fontsize="8",
                    arrowhead="normal",
                    arrowsize="0.5",
                )
                continue

            if isinstance(e, ExternalEntity):
                self.node(e.uniq_name, e.name,shape="box")
                continue

            if isinstance(e, DataStore):
                self.attr("node", shape="cylinder")
                self.node(e.uniq_name, e.name, shape="cylinder")
                continue

            if isinstance(e, TechnicalAsset):
                self.attr("node", shape="circle")
                self.node(e.uniq_name, e.name, shape="circle")
                continue
