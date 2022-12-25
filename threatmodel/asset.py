from .node import Construct
from .otm import OpenThreatModelAsset, OpenThreatModelAssetRisk
from .score import Score


class Asset(Construct):
    def __init__(self, scope: Construct, name: str, *, confidentiality: Score, integrity: Score, availability: Score, description: str = "") -> None:
        super().__init__(scope, name)

        self.description = description
        self.confidentiality = confidentiality
        self.integrity = integrity
        self.availability = availability

    @property 
    def average_asset_score(self) -> float:
        return (self.confidentiality + self.integrity + self.availability) / 3

    @property
    def otm(self) -> "OpenThreatModelAsset":
        return OpenThreatModelAsset(
            name=self.name,
            id=self.id,
            risk=OpenThreatModelAssetRisk(
                confidentiality=self.confidentiality,
                integrity=self.integrity,
                availability=self.availability,
            ),
            description=self.description,
        )

