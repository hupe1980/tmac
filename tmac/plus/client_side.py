from typing import Any

from diagrams.onprem import client

from ..component import ExternalEntity, Machine, Encryption, Technology
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

