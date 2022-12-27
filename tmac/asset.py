from .id import unique_id
from .node import Construct
from .otm import OpenThreatModelAsset, OpenThreatModelAssetRisk
from .score import Score


class Asset(Construct):
    def __init__(self, scope: Construct, name: str, *, confidentiality: Score, integrity: Score, availability: Score, description: str = "") -> None:
        super().__init__(scope, unique_id(name))

        self.name = name
        self.description = description
        self.confidentiality = confidentiality
        self.integrity = integrity
        self.availability = availability

    @property 
    def average_score(self) -> float:
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

