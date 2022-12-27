import graphviz


class DataFlowDiagram(graphviz.Digraph):
    def __init__(self, title: str, hide_data_flow_labels: bool = False) -> None:
        super().__init__(title, engine='fdp')

        self.attr("graph",
                  fontname="Arial",
                  fontsize="20",
                  overlap="false",
                  labelloc="t",
                  rankdir="TB",
                  outputorder="nodesfirst",
                  )

        self.attr("node",
                  fontname="Arial",
                  fontsize="12",
                  margin="0.02",
                  )

        self.attr("edge",
                  shape="none",
                  fontname="Arial",
                  fontsize="8",
                  arrowhead="normal",
                  arrowsize="0.5",
                  )

        self._hide_data_flow_labels = hide_data_flow_labels

    def add_data_flow(self, tail_name: str, head_name: str, label: str = "", bidirectional: bool = False, **overwrites: str) -> None:
        dir = "forward"
        if bidirectional:
            dir = "both"

        self.edge(tail_name, head_name,
                  label=None if self._hide_data_flow_labels else label,
                  dir=dir,
                  **overwrites,
                  )

    def add_asset(self, name: str, label: str, shape: str, **overwrites: str) -> None:
        self.node(name, label, shape=shape, **overwrites)
