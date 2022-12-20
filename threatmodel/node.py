from typing import Dict, List, Optional

class Node:
    @staticmethod
    def of(construct: "Construct") -> "Node":
        return construct.node

    def __init__(self, host: "Construct", scope: Optional["Construct"] = None, id: str = "") -> None:
        self.id = id
        self.scope = scope

        self._host = host
        self._locked = False
        self._children: Dict[str, "Construct"] = dict()

        if scope is not None:
            scope.node._add_child(host, self.id)

    def find_child(self, id: str) -> Optional["Construct"]:
        return self._children.get(id)

    def find_all(self)-> List["Construct"]:
        ret: List["Construct"] = list()

        def visit(c):
            ret.append(c)

            for c in c.node.children():
                visit(c)

        visit(self._host)

        return ret
    
    def children(self):
        return list(self._children.values())

    def _lock(self):
        self._locked = True

    def _add_child(self, child: "Construct", id: str) -> None:
         self._children[id] = child


class Construct:
    def __init__(self, scope: Optional["Construct"], id: str) -> None:
        self.node = Node(self, scope, id)