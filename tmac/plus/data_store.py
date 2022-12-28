from typing import Any
from diagrams.onprem import database
from diagrams.generic.database import SQL
from diagrams.generic.storage import Storage

from ..component import DataStore, Technology
from ..diagram import DiagramNode
from ..node import Construct


class Database(DataStore):
    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(
            scope,
            name,
            technology=Technology.DATABASE,
            **kwargs,
        )

    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_type(self.id, self.name, node_type=getattr(database, self.vendor, SQL))


class FileServer(DataStore):
    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(
            scope,
            name,
            technology=Technology.FILE_SERVER,
            **kwargs,
        )
    
    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_type(self.id, self.name, node_type=Storage)
