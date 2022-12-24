from enum import IntEnum
from .node import Construct
from .otm import OpenThreatModelAsset, OpenThreatModelAssetRisk

class Confidentiality(IntEnum):
    NONE = 0
    LOW = 20
    MEDIUM = 40
    HIGH = 60
    VERY_HIGH = 80
    CRITICAL = 100

class Integrity(IntEnum):
    NONE = 0
    LOW = 20
    MEDIUM = 40
    HIGH = 60
    VERY_HIGH = 80
    CRITICAL = 100

class Availability(IntEnum):
    NONE = 0
    LOW = 20
    MEDIUM = 40
    HIGH = 60
    VERY_HIGH = 80
    CRITICAL = 100


class Asset(Construct):
    def __init__(self, scope: Construct, name: str, confidentiality: Confidentiality, integrity: Integrity, availability: Availability, description: str = "") -> None:
        super().__init__(scope, name)

        self.description = description
        self.confidentiality = confidentiality
        self.integrity = integrity
        self.availability = availability

    @property 
    def average_asset_score(self):
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

