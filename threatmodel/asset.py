from .node import Construct
from .otm import OpenThreatModelAsset


class Asset(Construct):
    def __init__(self, scope: Construct, name: str, description: str = "") -> None:
        super().__init__(scope, name)

        self.description = description

    @property
    def otm(self) -> "OpenThreatModelAsset":
        return OpenThreatModelAsset(
            name=self.name,
            id=self.id,
            description=self.description,
        )
