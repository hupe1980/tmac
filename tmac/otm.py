import json
from abc import ABC
from typing import List, Dict, Any


class OpenThreatModelEncoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, set):
            return list(o)
        return o.__dict__


class BaseOpenThreatModel(ABC):
    def to_json(self, indent: int = 4) -> str:
        return json.dumps(self, indent=indent, cls=OpenThreatModelEncoder)

    def __str__(self) -> str:
        return self.to_json(indent=4)


class OpenThreatModelProject(BaseOpenThreatModel):
    def __init__(
        self,
        name: str,
        id: str,
        description: str = "",
        owner: str = "",
        owner_contact: str = "",
        tags: List[str] = list(),
        attributes: Dict[str, str] = dict(),
    ) -> None:
        self.name = name
        self.id = id
        self.description = description
        self.owner = owner
        self.ownerContact = owner_contact
        self.tags = set(tags)
        self.attributes = attributes


class OpenThreatModelAsset(BaseOpenThreatModel):
    def __init__(
        self,
        id: str,
        name: str,
        risk: "OpenThreatModelAssetRisk",
        description: str = "",
        attributes: Dict[str, str] = dict(),
    ) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.risk = risk
        self.attributes = attributes


class OpenThreatModelAssetRisk(BaseOpenThreatModel):
    def __init__(
        self, confidentiality: int, integrity: int, availability: int, comment: str = ""
    ) -> None:
        self.confidentiality = confidentiality
        self.integrity = integrity
        self.availability = availability
        self.comment = comment


class OpenThreatModelComponent(BaseOpenThreatModel):
    def __init__(
        self,
        id: str,
        name: str,
        type: str,
        tags: List[str] = list(),
        description: str = "",
        attributes: Dict[str, str] = dict(),
    ) -> None:
        self.id = id
        self.name = name
        self.type = type
        self.tags = set(tags)
        self.description = description
        self.attributes = attributes


class OpenThreatModelDataFlow(BaseOpenThreatModel):
    def __init__(
        self,
        id: str,
        name: str,
        source: str,
        destination: str,
        description: str = "",
        tags: List[str] = list(),
        bidirectional: bool = False,
        assets: List[str] = list(),
        threats: List["OpenThreatModelThreatInstance"] = list(),
        attributes: Dict[str, str] = dict(),
    ) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.tags = tags
        self.bidirectional = bidirectional
        self.source = source
        self.destination = destination
        self.assets = set(assets)
        self.threats = set(threats)
        self.attributes = attributes


class OpenThreatModelThreatRisk(BaseOpenThreatModel):
    def __init__(
        self,
        likelihood: int,
        impact: int,
        likelihood_comment: str = "",
        impact_comment: str = "",
    ) -> None:
        self.likelihood = likelihood
        self.impact = impact
        self.likelihoodComment = likelihood_comment
        self.impactComment = impact_comment


class OpenThreatModelThreat(BaseOpenThreatModel):
    def __init__(
        self,
        id: str,
        name: str,
        description: str = "",
        categories: List[str] = list(),
        cwes: List[str] = list(),
        attributes: Dict[str, str] = dict(),
    ) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.categories = set(categories)
        self.cwes = set(cwes)
        self.attributes = attributes


class OpenThreatModelThreatInstance(BaseOpenThreatModel):
    def __init__(self, threat: str, state: str) -> None:
        self.threat = threat
        self.state = state

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OpenThreatModelThreatInstance):
            return False
        return self.threat == other.threat

    def __hash__(self) -> int:
        return id(self.threat)


class OpenThreatModelMitigation(BaseOpenThreatModel):
    def __init__(
        self,
        id: str,
        name: str,
        description: str = "",
        risk_reduction: int = 0,
        attributes: Dict[str, str] = dict(),
    ) -> None:
        self.id = id
        self.name = name
        self.description = description
        self.riskReduction = risk_reduction
        self.attributes = attributes


class OpenThreatModelMigrationInstance(BaseOpenThreatModel):
    def __init__(self, mitigation: str, state: str) -> None:
        self.mitigation = mitigation
        self.state = state

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OpenThreatModelMigrationInstance):
            return False
        return self.mitigation == other.mitigation

    def __hash__(self) -> int:
        return id(self.mitigation)


class OpenThreatModel(BaseOpenThreatModel):
    def __init__(
        self,
        project: "OpenThreatModelProject",
        assets: List["OpenThreatModelAsset"] = list(),
        components: List["OpenThreatModelComponent"] = list(),
        data_flows: List["OpenThreatModelDataFlow"] = list(),
        threats: List["OpenThreatModelThreat"] = list(),
        mitigations: List["OpenThreatModelMitigation"] = list(),
    ) -> None:
        self.otmVersion = "0.1.0"
        self.project = project
        self.assets = set(assets)
        self.components = set(components)
        self.dataflows = set(data_flows)
        self.threats = set(threats)
        self.mitigations = set(mitigations)
