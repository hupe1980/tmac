from abc import ABCMeta, abstractproperty, abstractmethod
from typing import List, TYPE_CHECKING

from .node import Construct, unique_id


if TYPE_CHECKING:
    pass
    

class Element(Construct, metaclass=ABCMeta):
    """A generic model element"""

    def __init__(self, scope: Construct, name: str, description: str = ""):
        super().__init__(scope, unique_id(name))

        self.name = name
        self.description = description
        self.out_of_scope = False

        # import when need to avoid circular import
        from .model import Model
        self._model = Model.of(self)

        self.node.add_validation(self.validate)

    def validate(self) -> List[str]:
        return [] 
