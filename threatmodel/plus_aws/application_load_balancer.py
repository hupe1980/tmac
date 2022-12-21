from typing import Any

from ..asset import Process, Machine, Encryption, Technology
from ..control import Control
from ..node import Construct


class ApplicationLoadBalancer(Process):
    def __init__(self, scope: Construct, name: str, waf: bool = False, **kwargs: Any):
        super().__init__(scope, name,
                         machine=Machine.VIRTUAL,
                         technology=Technology.LOAD_BALANCER,
                         uses_environment_variables=False,
                         human_use=False,
                         internet_facing=False,
                         encryption=Encryption.NONE,
                         multi_tenant=True,
                         redundant=True,
                         custom_developed_parts=False,
                         **kwargs)

        self.add_controls(Control.BOUNDS_CHECKING)

        if waf:
            self.add_controls(Control.WAF)
