from typing import TYPE_CHECKING
from .node import Construct
from .element import Element

if TYPE_CHECKING:
    pass

class TrustBoundary(Element):
    """Trust zone changes as data flows through the system."""

    def __init__(self, scope: Construct, name: str) -> None:
        super().__init__(scope, name)
