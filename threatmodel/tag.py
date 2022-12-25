from typing import List, Set

class TagMixin:
    def __init__(self) -> None:
        self._tags: Set[str] = set()

    @property
    def tags(self) -> List[str]:
        return list(self._tags)

    def add_tags(self, *tags: str) -> None:
        for tag in tags:
            self._tags.add(tag)

    def has_tag(self, tag: str) -> bool:
        return tag in self._tags
