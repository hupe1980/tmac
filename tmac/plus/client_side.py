from typing import Any

from diagrams.onprem import client

from ..component import Actor, ExternalEntity, Machine, Encryption, Technology
from ..diagram import DiagramNode
from ..node import Construct


class Browser(ExternalEntity):
    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name,
                         machine=Machine.PHYSICAL,
                         technology=Technology.BROWSER,
                         human_use=True,
                         encryption=Encryption.NONE,
                         multi_tenant=False,
                         redundant=False,
                         custom_developed_parts=False,
                         **kwargs)


class User(Actor):
    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name, is_human=True, **kwargs)
    
    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_type(self.id, self.name, node_type=client.User)
