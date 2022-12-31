from .element import Element
from .node import Construct
from .otm import OpenThreatModelAsset, OpenThreatModelAssetRisk
from .score import Score


class Asset(Element):
    def __init__(
        self,
        scope: Construct,
        name: str,
        *,
        confidentiality: Score,
        integrity: Score,
        availability: Score,
        description: str = "",
        is_pii: bool = False,
        out_of_scope: bool = False,
    ) -> None:
        super().__init__(scope, name, description=description)

        self.name = name
        self.description = description
        self.confidentiality = confidentiality
        self.integrity = integrity
        self.availability = availability
        self.is_pii = is_pii

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
            attributes={
                "is_pii": str(self.is_pii),
            },
        )
