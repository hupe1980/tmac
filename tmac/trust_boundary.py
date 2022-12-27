from typing import TYPE_CHECKING
from .node import Construct
from .element import Element

if TYPE_CHECKING:
    pass

class TrustBoundary(Element):
    """Trust boundary."""

    def __init__(self, scope: Construct, name: str, description: str = "",) -> None:
        super().__init__(scope, name, description=description)
