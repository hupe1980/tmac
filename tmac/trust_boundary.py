from typing import TYPE_CHECKING, List, Optional, Set

from .diagram import DiagramCluster
from .element import Element
from .node import Construct

if TYPE_CHECKING:
    from .component import Component


class TrustBoundary(Element):
    """Trust boundary."""

    def __init__(
        self,
        scope: Construct,
        name: str,
        description: str = "",
        trust_boundary: Optional["TrustBoundary"] = None,
    ) -> None:
        super().__init__(scope, name, description=description)

        self.trust_boundary = trust_boundary

    @property
    def components(self) -> List["Component"]:
        components: Set["Component"] = set()
        for c in self._model.components:
            if c.trust_boundary == self:
                components.add(c)

        return list(components)

    @property
    def children(self) -> List["TrustBoundary"]:
        children: Set["TrustBoundary"] = set()
        for tb in self._model.trust_boundaries:
            if tb.trust_boundary == self:
                children.add(tb)

        return list(children)

    @property
    def parents(self) -> List["TrustBoundary"]:
        result = []
        parent = self.trust_boundary
        while parent is not None:
            result.append(parent)
            parent = parent.trust_boundary
        return result

    @property
    def diagram_cluster(self) -> "DiagramCluster":
        return DiagramCluster(
            label=self.name,
            nodes=[c.diagram_node for c in self.components],
            clusters=[tb.diagram_cluster for tb in self.children],
        )
