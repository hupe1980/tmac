from typing import Any

from ..asset import ExternalEntity, Machine, Encryption, Technology
from ..node import Construct


class Browser(ExternalEntity):
    def __init__(self, scope: Construct, name: str, **kwargs: Any):
        super().__init__(scope, name,
                         machine=Machine.PHYSICAL,
                         technology=Technology.BROWSER,
                         uses_environment_variables=False,
                         human_use=True,
                         internet_facing=True,
                         encryption=Encryption.NONE,
                         multi_tenant=False,
                         redundant=False,
                         custom_developed_parts=False,
                         **kwargs)
