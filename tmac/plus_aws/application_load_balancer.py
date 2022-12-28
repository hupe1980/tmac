from typing import Any
from diagrams.aws.network import ElbApplicationLoadBalancer

from ..component import Process, Machine, Encryption, Technology
from ..diagram import DiagramNode
from ..node import Construct


class ApplicationLoadBalancer(Process):
    def __init__(self, scope: Construct, name: str, waf: bool = False, **kwargs: Any):
        super().__init__(scope, name,
                         machine=Machine.VIRTUAL,
                         technology=Technology.LOAD_BALANCER,
                         human_use=False,
                         internet_facing=False,
                         encryption=Encryption.NONE,
                         multi_tenant=True,
                         redundant=True,
                         custom_developed_parts=False,
                         **kwargs)

    @property
    def diagram_node(self) -> "DiagramNode":
        return DiagramNode.from_type(self.id, self.name, node_type=ElbApplicationLoadBalancer)

