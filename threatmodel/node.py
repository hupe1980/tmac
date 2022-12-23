from typing import Dict, List, Set, Optional
import uuid


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

    def find_all(self) -> List["Construct"]:
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
    def __init__(self, scope: Optional["Construct"], name: str) -> None:
        self.name = name
        self.id = self._uuid()
        self.node = Node(self, scope, self.id)

    def _uuid(self) -> str:
        uid = str(uuid.uuid4())[:8]
        return f"{self.name}_{uid}"


class TagMixin:
    _tags: Set[str] = set()

    @property
    def tags(self) -> List[str]:
        return list(self._tags)

    def add_tags(self, *tags: str) -> None:
        for tag in tags:
            self._tags.add(tag)

    def has_tag(self, tag: str) -> bool:
        return tag in self._tags
