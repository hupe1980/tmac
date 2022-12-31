from typing import Dict, Optional, Set, Type, List

from diagrams import Diagram, Edge, Node, Cluster


class DiagramCluster:
    def __init__(self, label: str, nodes: List["DiagramNode"], clusters: List["DiagramCluster"]) -> None:
        self._label = label
        self._nodes = nodes
        self._clusters = clusters

    def render(self, nodes: Dict[str, "Node"]) -> None:
        with Cluster(self._label):
            for n in self._nodes:
                n.render(nodes)
            for cluster in self._clusters:
                cluster.render(nodes)

class DiagramEdge:
    def __init__(
        self,
        source_id: str,
        target_id: str,
        label: str = "",
        bidirectional: bool = False,
        **overwrite_edge_attrs: str,
    ) -> None:
        self._source_id = source_id
        self._target_id = target_id
        self._label = label
        self._bidirectional = bidirectional
        self._overwrite_edge_attrs = overwrite_edge_attrs

    def render(
        self, nodes: Dict[str, "Node"], hide_data_flow_labels: bool = False
    ) -> "Node":
        return nodes[self._source_id].connect(
            nodes[self._target_id],
            Edge(
                label="" if hide_data_flow_labels else self._label,
                forward=True,
                reverse=self._bidirectional,
                **self._overwrite_edge_attrs,
            ),
        )


class DiagramNode:
    def __init__(
        self,
        id: str,
        label: str,
        *,
        node_type: Optional[Type["Node"]] = None,
        overwrites: Dict[str, str] = dict(),
    ) -> None:
        self.id = id
        self._label = label
        self._node_type = node_type
        self._overwrites = overwrites

    @classmethod
    def from_attr(cls, id: str, label: str, **overwrites: str) -> "DiagramNode":
        return cls(id, label, overwrites=overwrites)

    @classmethod
    def from_type(
        cls, id: str, label: str, node_type: Type["Node"], **overwrites: str
    ) -> "DiagramNode":
        return cls(id, label, node_type=node_type, overwrites=overwrites)

    def render(self, nodes: Dict[str, "Node"]) -> None:
        if self._node_type is not None:
            node = self._node_type(self._label, nodeid=self.id, **self._overwrites)
            nodes[node.nodeid] = node
        else:
            node = Node(self._label, nodeid=self.id, **self._overwrites)
            nodes[node.nodeid] = node


class DataFlowDiagram:
    def __init__(
        self, title: str, is_notebook: bool = False, hide_data_flow_labels: bool = False
    ) -> None:
        self.title = title

        self._is_notebook = is_notebook
        self._hide_data_flow_labels = hide_data_flow_labels
        
        self._clusters: Set["DiagramCluster"] = set()
        self._nodes: Dict[str, "DiagramNode"] = dict()
        self._edges: Set["DiagramEdge"] = set()

    def add_cluster(self, cluster: "DiagramCluster") -> None:
        self._clusters.add(cluster)

    def add_node(self, node: "DiagramNode") -> None:
        self._nodes[node.id] = node

    def add_edge(self, edge: "DiagramEdge") -> None:
        self._edges.add(edge)

    def show(self) -> None:
        return self._render(show=True)

    def save(self, filename: str = "dfd") -> None:
        return self._render(show=False, filename=filename)

    def _render(self, show: bool, filename: str = "dfd") -> None:
        with Diagram(show=show, filename=filename) as diagram:
            nodes: Dict[str, "Node"] = dict()

            for n in self._nodes.values():
                n.render(nodes)

            for c in self._clusters:
                c.render(nodes)

            for f in self._edges:
                f.render(nodes)

        if self._is_notebook:
            try:
                from IPython import display

                display.display(diagram)
            except ImportError:
                pass
